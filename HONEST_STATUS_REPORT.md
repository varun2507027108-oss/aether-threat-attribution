# AETHER — Honest Status Report

**NTRO PS-26151 · Smart India Hackathon 2026**
**Team VIHAR · Dark Web Threat Actor De-Anonymization**
**September 2026**

This is the second edition of this report. The first was written against the
pre-hardening repository. Everything below was **re-verified against the running
code and database**, not carried over from the earlier draft. Where the earlier
report was wrong, this one says so.

Read section 4 first. The most serious finding is not on the screen — it is
inside the custody ledger.

---

## 1. What AETHER is, in one minute

AETHER correlates lawful open-source artefacts — darknet forum posts, PGP keys,
Bitcoin wallets, TLS certificates, CT logs, posting timestamps — into one suspect
profile, and keeps a tamper-evident record of every step so the result can be
explained in court.

It does not break encryption and it does not attack Tor. It correlates evidence
an authorised investigator is already permitted to hold.

Three parts: a **Next.js** console, a **FastAPI** backend running **10 analysis
modules**, and a database holding cases, evidence and the custody chain.

| Measured on 2026-09-29 | Value |
|---|---|
| Backend tests | **470 passed**, 0 failed |
| Pipeline modules | **10** (was 9) |
| Frontend lint | **0 errors** (was 9) |
| Hard-coded colour values in the UI | **0** (was 500) |
| Custody entries in the dev database | 197 |
| Custody entries carrying a cryptographic signature | **0** |

---

## 2. What is genuinely real

Each of these runs on the server, stores results, and has automated tests.

| Capability | What actually works | Honest limitation |
|---|---|---|
| **SHA-256 custody chain** | Real hash chain in the database. A verify endpoint re-walks every block. An **offline verifier** (`/verify.html`) recomputes the whole chain in the browser with no server. | Off-chain anchoring is self-referential by default (see §3). |
| **Ed25519 entry signing** | Every custody entry can be signed; canonical serialisation is fixed. | **Not enabled.** `AETHER_SIGNING_KEY` is unset, so **0 of 197** entries are signed. |
| **RFC 3161 timestamping** | `AETHER_TSA_URL` support for external time anchors. | Not configured. All 92 checkpoints are `internal`. |
| **Stylometry ensemble** | Cosine over char/word n-grams, **Burrows' Delta**, **LZW normalised compression distance**, Unicode script profiling, calibrated threshold and false-positive rate. | A **40-token minimum** — below it Burrows' Delta is refused and the ensemble reports `degraded`, which is correct behaviour, not a bug. |
| **Live/mock intel providers** | Shodan, Censys and crt.sh clients with a per-record provenance tag. The OSINT module **does** call the provider. | Default mode is `mock`. Live mode needs API keys. |
| **TLS + certificate analysis** | Real JARM evaluation, commodity-certificate detection, CT log overlap. | Active probing is **off by default** for investigator OPSEC. |
| **Scoring engine** | Log-likelihood-ratio fusion, contradiction penalties, prior odds, full contribution breakdown. | Some pipeline inputs are still fixed (§3). |
| **Async pipeline + SSE** | 10 modules run concurrently with a live job-state stream. | — |
| **Role-based access** | Multi-key auth with `investigator` / `auditor` roles, `can_write`, `can_confirm_export`, per-key and per-IP rate limits. **New since the last report.** | Keys, not accounts. No named users yet. |
| **Human-in-the-loop export** | STIX / CSV / PDF are refused with `409` until an investigator affirms release. Custody export is deliberately ungated so third parties can audit. **New.** | — |
| **DPDP retention** | Configurable retention with a purge path and audit record. **New.** | — |
| **Exports** | STIX 2.1 via the official `stix2` library, CSV with formula-injection defence, **a sealed PDF certificate**, and a standalone custody ledger. **PDF is new.** | — |
| **Security** | Timing-safe key comparison, SSRF guard rejecting private and metadata targets, payload limits, security headers, OPSEC rule forbidding direct `.onion` fetches. | The dev key is still compiled into the frontend (§5). |
| **Containerisation** | `docker compose up --build` runs Postgres, Tor, API and console together. **New.** | Image build not yet verified end-to-end. |

---

## 3. What is still demo — never call it live

This is unchanged in substance from the last report, and the code lines below
were confirmed by reading them, not inferred.

| Module | Code | What actually happens |
|---|---|---|
| **Origin IP** | `investigation.py:861-863` | Returns `185.220.101.42`, `Munich, Bavaria, Germany`, `AS9009 M247 Europe`. All three are literals. No probe occurs. The same IP is hardcoded again at `investigation.py:187`. |
| **Visual dHash** | `investigation.py:645-646` | Compares two fixed strings, `a3f5c2b189e47d10` and `...d14`. The hash function `compute_simple_dhash` in `intel.py` samples 65 raw **bytes** — it is not a real perceptual image hash. |
| **Favicon mmh3** | provider fixture | `-129482710` is the mock provider's deterministic fixture. Correctly tagged `DEMO_DATA`. |
| **JARM TLS** | `intel.py` | Falls back to a fixed fingerprint `29d29d00…`. Honestly reports `active_probe_conducted: false`, `mode: PASSIVE_STORED`. |
| **Bitcoin clustering** | pipeline | Runs on two built-in demo transactions. |
| **Diurnal** | pipeline | Feeds synthetic timestamps when none are supplied. |
| **CT log** | pipeline | Queries for the hardcoded `185.220.101.42`, not the actual target. |

**Provenance labelling is much better than the last report said.** Eight of ten
evidence rows are now correctly `DEMO_DATA`. Two are not:

```
PGP_KEY    LIVE_SOURCE   4D9E 27BC 918A …
BTC_WALLET LIVE_SOURCE   bc1qa5wkgaew2d …
```

Both are the analyst's **own preset input** echoed back, not an independent
measurement. `LIVE_SOURCE` is the wrong word; `INVESTIGATOR_SUPPLIED` is honest.

---

## 4. The critical finding: the sealed ledger contains false statements

This is the most serious issue in the project, and the previous report did not
find it. The problem is not a label on screen. **The fabrications are inside the
tamper-evident custody chain** — the exact artifact the admissibility story
depends on. Actual rows read from the database:

```
seq=3  Certificate Transparency log queried for 185.220.101.42: N…
seq=4  Favicon mmh3 hash calculated (-129482710); matched Shodan cluster facet
seq=6  PGP key fingerprint verified (40FA7D3C). Reused across 3 darknet forums
seq=9  Visual logo dHash similarity evaluated (Hamming: 1, Sim: 0.98)
seq=11 JARM TLS fingerprint evaluated: Tor Hidden Service Onion G…
```

Read that as a court would. The chain says *"a Shodan cluster facet was
matched"*, *"this key was reused across three darknet forums"*, and *"a
certificate transparency log was queried"*. None of those things happened. The
hashes verify, so the chain looks impeccable — while vouching for findings
nobody measured. **An unbroken hash chain over invented content is worse than no
chain, because it lends false confidence.**

Two of those five statements are not even from a module: the "reused across 3
darknet forums" phrase is prose hardcoded at `investigation.py:328`.

**Fix order:** every custody string must be built from a value the engine
actually produced, and a module that did not run must append *no* entry at all.
A ledger that records "this was not measured" is honest; a ledger that records a
finding is only allowed to do so when the finding exists.

---

## 5. Critical issues, ranked

### 1. Stop sealing unmeasured findings into the custody chain
*Section 4.* The admissibility backbone vouches for fabrications. **This is now
the top priority** — ahead of everything below.

### 2. Opening a case re-runs the whole pipeline and destroys prior evidence
`cases.py:189-206` calls `run_full_investigation` on a plain `GET`. That function
executes `case.evidence_records.clear()` at `investigation.py:838` and appends
fresh custody rows plus a fresh audit row.

The dev database holds **95 recorded pipeline runs**, and case 16 ran **twice
96 ms apart** — once from the start call, once from the dashboard's fetch. So
simply looking at a case rewrites its evidence. Evidence that changes when you
look at it is not evidence.

Related: the endpoint falls back to `target=… or "185.220.101.42"`, so a case
with no stored target is silently investigated as a Tor exit node.

### 3. The offline fallback still invents a 94.8% case
`api.ts:788, 1030, 1100, 1117, 1190`. With the backend down, the console renders
a complete, confident, fabricated case. This was flagged in the last report and
is **still open**. Our own rule says show SOURCE UNAVAILABLE, never invent.

### 4. The dev API key is still compiled into the frontend
`api.ts:35` — `process.env.NEXT_PUBLIC_AETHER_API_KEY || "aether-investigator-dev-key-2026"`.
Anyone loading the page receives a working key. **Still open.**

### 5. Most investigator actions are not audited
`record_audit_log()` exists in `security.py:620` and **is never called**. Only
five action types are ever written:

```
95  FULL_INVESTIGATION_ANALYSIS
12  RETENTION_PURGE
 9  START_INVESTIGATION_JOB
 7  VERIFY_CUSTODY_CHAIN
 3  START_INVESTIGATION
```

Viewing a case, adding a custody entry, affirming an export in the UI — none are
audited. For a tool whose pitch is chain of custody, that is a gap.

**Correction to the last report:** it claimed an audit-log bug where an evidence
ID string was passed where an integer case number belongs, crashing on
PostgreSQL. That is not the current bug — every existing writer passes `case.id`
correctly. The real problem is the dead function above.

### 6. Signatures and external anchoring are implemented but switched off
`0 / 197` entries signed; `92 / 92` checkpoints internal. Set
`AETHER_SIGNING_KEY` and `AETHER_TSA_URL` and both switch on, but until a judge
sees one signed entry and one external timestamp, the custody claim is weaker
than the documentation implies.

---

## 6. Missing entirely

None of these exist in the repository.

| Missing | Why it matters |
|---|---|
| **Tor/SOCKS5 collection of `.onion` content** | The Tor proxy ships in compose and is used for opt-in active probing, but no module ever fetches an authorised target's page or favicon. Every collection step stays synthetic. |
| **Shodan/Censys in live mode for a real case** | Clients exist and are called; default is `mock`. Real provenance tags need a live key. |
| **Neo4j** | We generate Cypher text. No client, no server. The console shows a "Neo4j Bolt URL" field that does nothing. |
| **Elasticsearch** | Absent. No search over stored evidence. |
| **Trained stylometry model** | Still n-gram statistics, not the neural model early slides mentioned. This was a documented decision, and the statistical ensemble is defensible on its own terms. |
| **Named user accounts** | RBAC exists but identities are API keys, not people. |
| **Stored-result retrieval** | Covered in issue 2. |

---

## 7. Corrections to the previous report

Where the earlier document was wrong, corrected:

| Previous claim | Reality |
|---|---|
| 73 / 74 tests, one failing | **470 / 470 passing.** The failing test is fixed. |
| 9 modules | **10** — certificate transparency was added. |
| "RBAC missing — one shared API key" | **Delivered** as multi-key RBAC with roles and rate limits. |
| "Court / statutory PDF missing" | **Exists** at `/api/cases/{id}/export/certificate`. |
| "Shodan/Censys wired but modules never call it" | The OSINT module **does** call `query_ip_intelligence`. |
| "Audit-log FK bug crashes PostgreSQL" | Not the current bug. `record_audit_log` is dead code — a different and more serious problem. |
| "Tor/SOCKS5 crawler missing" | Still true for collection. Tor is wired for opt-in probing. |
| "Some rows stamped LIVE_SOURCE with no network touched" | Largely fixed: 8 of 10 rows are now `DEMO_DATA`. Two remain mislabelled. |

---

## 8. Plan to finish

Ordered so that **truth is fixed before capability is added**. Nothing in phase 2
should start until phase 1 is done and the suite is green.

### Phase 1 — Make the record true (3–5 days)

1. Rebuild every custody string from a produced value; no module that did not run
   appends an entry.
2. Make `GET /investigation` read stored results. Persist the full result and
   rehydrate it; stop clearing evidence on read.
3. Wire `record_audit_log` into case view, evidence add and export affirm.
4. Replace the offline fallback with an explicit empty state and a
   "SOURCE UNAVAILABLE" banner.
5. Remove the dev key from the bundle; require an injected key.
6. Relabel `LIVE_SOURCE` → `INVESTIGATOR_SUPPLIED` for analyst-supplied inputs.
7. Delete the fabricated "reused across 3 forums" string.

**Showable:** open any case, and every line in the ledger is either a real
measurement or an explicit statement that it was not measured.

### Phase 2 — Real collection (1–2 weeks)

Tor SOCKS5 fetch of authorised targets, live favicon and JARM from real
responses, Shodan/Censys/crt.sh with real keys, timestamps and transactions fed
from investigator input rather than fixtures. Turn on `AETHER_SIGNING_KEY` and
`AETHER_TSA_URL`.

**Showable:** provenance flips to `LIVE_SOURCE` only because a real request
happened, and the custody chain carries signatures and external timestamps.

### Phase 3 — Persistence and scale (1–2 weeks)

Stored-result retrieval done properly, cross-case search (Elasticsearch or
Postgres full-text), optional Neo4j import for graph queries, named accounts
mapped onto the existing role checks.

**Showable:** old cases open instantly and identically; cross-case search works.

### Phase 4 — Package (1 week)

Sealed court-style PDF with the full evidence table, docker-compose deploy check
against PostgreSQL, and a rehearsed demo on a clearly labelled benchmark case.

**Showable:** a complete, deployable, honest submission.

### What we should not build

A crawler that touches unauthorised targets, a scraping shortcut that bypasses
lawful access, or any button that implies we are attacking Tor. They add legal
risk and no points. PS-26151 rewards lawful correlation and explainable
confidence — which is exactly what the four phases above deliver.

---

## 9. The honest one-line pitch

AETHER has a real forensic backbone — a verifiable custody chain, four genuine
analysis engines, standards-based STIX 2.1 export, role-based access, and a
hardened API — running on clearly labelled benchmark data.

Two things are true today and we should say both out loud: the pipeline's
*algorithms* are real while most of its *inputs* are fixtures, and the custody
ledger currently seals statements that no measurement produced. The first is a
data-source problem we can solve with API keys. The second is a correctness
problem, and it is the one we fix first.
