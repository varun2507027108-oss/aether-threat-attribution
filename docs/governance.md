# Data Governance — DPDP Act 2023

**Project AETHER · NTRO PS-26151**

This document records how AETHER handles personal data, who may do what, and
under what conditions data leaves the system or is destroyed. It is written for
the investigating officer, the auditor, and opposing counsel, and each control
below names the code that enforces it so the claim can be checked rather than
believed.

The governing statute is the **Digital Personal Data Protection Act, 2023**
(DPDP Act). Two of its principles drive almost every decision here:

- **Purpose limitation** — data collected for a specified investigative purpose
  may not be retained indefinitely once that purpose is exhausted.
- **Accountability** — the controller must be able to demonstrate what was done
  with the data, not merely assert that it followed the law.

---

## 1. Roles and separation of duties

| Role | Read cases | Export dossier | Append custody | Create cases | Affirm export |
|---|---|---|---|---|---|
| `investigator` | yes | yes | yes | yes | **yes** |
| `auditor` | yes | **no** | no | no | no |

Enforced by `app.security.require_write_access` and
`app.security.require_export_confirmation_role`.

An auditor can download the **custody ledger** (`/export/custody`) but not the
dossier. That asymmetry is deliberate: the ledger is the integrity record, and
`verify.html` exists so a third party can audit it. Gating the evidence of
tampering behind permission to tamper would invert the control.

An auditor cannot satisfy the export gate. A reviewer who can authorize their
own release has not reviewed anything.

Keys are configured in `AETHER_API_KEYS` as `role:key` pairs. An unrecognized
role is **rejected and logged**, never defaulted to investigator, so a typo in
configuration cannot silently escalate privilege. The legacy single
`AETHER_API_KEY` maps to `investigator` and remains fully supported.

Constant-time comparison is used for every key, and all candidates are compared
even after a match so response time reveals neither the matching position nor
the number of configured keys.

## 2. Rate limiting is per credential, not per IP

Buckets are keyed by `(key_id, client_ip)`. IP-only limiting means every
investigator behind one NAT or egress gateway shares a single budget, so a team
of ten cannot work: the ninth investigator is throttled because the eighth ran
a heavy module. Keying on the credential *in addition to* the IP bounds both
abuse from one key spraying across hosts, and abuse from one host rotating keys.

Unauthenticated traffic lands in a distinct `invalid-key` bucket rather than the
shared `anonymous` one, so it cannot be used to exhaust a budget and lock out
legitimate callers.

## 3. The export gate: machine proposes, human affirms

Every dossier-releasing export — STIX 2.1, the attribution CSV, and the statutory
certificate — returns **409** until an investigator has called:

```
POST /api/cases/{evidence_id}/confirm-export
```

The confirmation appends a **signed** custody entry:

```
EXPORT_CONFIRMED dossier_sha256=<hash> key=<key_id>
```

so the chain records both *who released the dossier* and *exactly what they
released*. `GET /api/cases/{evidence_id}/export/gate` reports the current state
without satisfying it.

**A confirmation is bound to a dossier hash, not to a case.** If the case changes
after an analyst confirms, the earlier confirmation does not carry over.
Otherwise a confirmation given for a partial dossier would silently authorize
release of a fuller one — the failure mode of a boolean flag.

The dossier hash covers only fields that actually appear in an export. Hashing
internal state the exporter never emits would produce a value that implies more
coverage than it has.

## 4. Retention and erasure

`AETHER_RETENTION_DAYS` (default 365) bounds how long a case is kept. Age is
measured from `created_at`, **not** from last activity: purpose limitation means
a case cannot be kept open forever by continuing to touch it. A zero or
unparsable value falls back to 365 rather than to "delete everything", because a
retention window of zero would destroy a case the instant it was created.

```
python scripts/purge_expired.py              # dry run (default)
python scripts/purge_expired.py --commit     # execute
python scripts/purge_expired.py --verify-chain
```

Dry-run is the default because a purge is irreversible. The operator must pass
`--commit` explicitly.

### The purge is itself evidence

A committed purge writes a manifest hash and a custody entry to a
**case-independent** chain (`case_id = 0`), which is verified by
`--verify-chain`.

This is the point worth defending. Logging the purge *inside* the case would
delete the only record that the deletion was authorized and lawful, at the same
moment it deleted everything else. The chain entry survives the destruction, so
the record of destruction is itself tamper-evident — the same guarantee the rest
of the system provides for evidence.

## 5. Investigator OPSEC

Collected data can deanonymize the investigator, not just the subject. These
controls are set in Phase 3 and are load-bearing for the others:

| Control | Env var | Default | Effect |
|---|---|---|---|
| Tor SOCKS transport | `AETHER_TOR_SOCKS_URL` | unset | per-module circuit isolation; onion fetches are blocked without it |
| Active probing | `AETHER_ACTIVE_PROBE_ENABLED` | `false` | TLS/JARM handshakes skipped unless proxied |
| Direct `.onion` fetch | — | always blocked | `is_safe_direct_fetch()` |

When active probing is enabled but no Tor proxy is configured, the probe is
**refused and reported as refused** rather than silently falling back to an
unproxied clearnet handshake. `resolve_tls_fingerprint()` reports
`status: "probe_skipped_no_tor"` so the withheld probe is visible to a reviewer.

## 6. Outbound data: what leaves the machine

| Destination | Allowlist | Purpose |
|---|---|---|
| `crt.sh` | exact hostname, HTTPS only | passive Certificate Transparency disclosure check |
| `api.shodan.io`, `search.censys.io`, `api.censys.io` | exact hostname, HTTPS only | authorized passive OSINT |

Enforced by `is_allowed_external_intel_url()`. Redirects are **not** followed, so
a redirect cannot walk off the allowlist. Subdomains, `http://`, loopback, and
link-local metadata addresses are all rejected.

`AETHER_INTEL_MODE=mock` (or the absence of `SHODAN_API_KEY`) routes all
intelligence through the offline corpus in `aether-backend/tests/fixtures/intel/`.
In mock mode the pipeline makes **no outbound requests at all**, which is what
keeps the test suite deterministic and air-gap friendly.

A note on provenance: `LiveProvider` does **not** fall back to a curated demo
record when a key is missing or an API call fails. "We queried a source and it
returned nothing" and "we hold a synthetic record for this exact IP" are
different facts, and conflating them is exactly the kind of provenance confusion
that invalidates evidence under
**Section 63, Bharatiya Sakshya Adhiniyam, 2023 (formerly s.65B, Indian Evidence Act, 1872)**.

## 7. Evidence integrity is not the same as authenticity

Every dossier carries its evidentiary caveat, and the offline verifier states it
on its face: a passing `verify.html` result means the file is **internally
consistent**, not that it is authentic, that its author is known, or that the
observations inside it are true. Internal consistency is necessary and never
sufficient.

Independent verification requires no network access, no key, and no cooperation
from the operator running the system.
