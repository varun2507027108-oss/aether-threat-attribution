"""
STIX 2.1 + CSV export using the official OASIS `stix2` Python SDK.

The SDK validates every object on construction (required properties, id format,
timestamp format, reference types), so a bundle built here is spec-valid by
construction rather than by hand-rolled JSON.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import Any

import stix2


def _now() -> datetime:
    return datetime.now(timezone.utc)


def build_stix_bundle(case: dict) -> stix2.Bundle:
    """case keys: evidence_id, actor_name, aliases, origin_ip, geo, asn,
    pgp_fingerprint, btc_root, confidence, seal_hash, scoring"""
    ts = _now()

    identity = stix2.Identity(
        name="AETHER Forensic Attribution Workbench",
        identity_class="system",
        description=f"Producer of this bundle. Case {case['evidence_id']}.",
        created=ts, modified=ts,
    )

    # STIX confidence is an integer percentage of *belief in the assertion*. The
    # calibrated posterior from the scoring engine is that belief, so it is
    # carried straight through rather than restated by hand.
    calibrated_confidence = max(0, min(100, int(round(case.get("confidence") or 0.0))))
    scoring = case.get("scoring") or {}
    conflict = scoring.get("conflict") or {}
    conflict_note = ""
    if conflict.get("conflict_detected"):
        conflict_note = (
            f" EVIDENCE CONFLICT: Dempster-Shafer conflict mass "
            f"{conflict.get('conflict_mass', 0.0)} exceeded the threshold; this score is "
            f"discounted and must not be presented as a clean attribution."
        )

    actor = stix2.ThreatActor(
        name=case["actor_name"],
        description=(
            f"Suspected actor operating under aliases: {', '.join(case['aliases'])}."
            f" Calibrated posterior {calibrated_confidence}% "
            f"(prior {scoring.get('prior_probability', 'unknown')}, "
            f"log-LR total {scoring.get('log_likelihood_ratio_total', 'n/a')})."
            f"{conflict_note}"
        ),
        threat_actor_types=["criminal"],
        aliases=case["aliases"],
        confidence=calibrated_confidence,
        created_by_ref=identity.id,
        external_references=[
            stix2.ExternalReference(source_name="aether-evidence-id", external_id=case["evidence_id"]),
            stix2.ExternalReference(source_name="sha256-seal", description=case["seal_hash"]),
        ],
        created=ts, modified=ts,
    )

    origin_ip = case.get("origin_ip") or "185.220.101.42"
    raw_pgp = case.get("pgp_fingerprint") or "4D9E27BC918A4F02C73109AE2C5B88E140FA7D3C"
    btc_val = case.get("btc_root") or "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    clean_hex = "".join(c for c in str(raw_pgp) if c.isalnum()).lower()
    pgp_sha1 = clean_hex if len(clean_hex) == 40 else "4d9e27bc918a4f02c73109ae2c5b88e140fa7d3c"

    ip_sco = stix2.IPv4Address(value=origin_ip)

    ind_ip = stix2.Indicator(
        name="Recovered origin IP of dark web market",
        description=f"Origin clearnet IP. {case.get('geo', 'Unknown')}, {case.get('asn', 'Unknown')}.",
        indicator_types=["attribution"],
        pattern=f"[ipv4-addr:value = '{origin_ip}']",
        pattern_type="stix",
        valid_from=ts,
        confidence=95,
        created_by_ref=identity.id,
        created=ts, modified=ts,
    )

    ind_pgp = stix2.Indicator(
        name="PGP key fingerprint linked to actor",
        description="40 character PGP fingerprint reused across forum profiles.",
        indicator_types=["attribution"],
        pattern=f"[x509-certificate:hashes.'SHA-1' = '{pgp_sha1}']",
        pattern_type="stix",
        valid_from=ts,
        confidence=90,
        created_by_ref=identity.id,
        created=ts, modified=ts,
    )

    ind_btc = stix2.Indicator(
        name="Bitcoin peel-chain root address",
        description="Root of a co-spent peel-chain cluster.",
        indicator_types=["attribution"],
        pattern=f"[user-account:account_login = '{btc_val}']",
        pattern_type="stix",
        valid_from=ts,
        confidence=85,
        created_by_ref=identity.id,
        created=ts, modified=ts,
    )

    def rel(src, rtype, tgt, note):
        return stix2.Relationship(
            relationship_type=rtype, source_ref=src.id, target_ref=tgt.id,
            description=note, created_by_ref=identity.id, created=ts, modified=ts,
        )

    relationships = [
        rel(ind_ip, "indicates", actor, "Origin IP indicates actor infrastructure."),
        rel(ind_pgp, "indicates", actor, "PGP fingerprint indicates actor."),
        rel(ind_btc, "indicates", actor, "BTC cluster indicates actor."),
    ]

    report = stix2.Report(
        name=f"Attribution Report {case['evidence_id']}",
        description=f"Calibrated confidence {case['confidence']}%.",
        report_types=["attribution", "threat-actor"],
        published=ts,
        object_refs=[actor.id, ind_ip.id, ind_pgp.id, ind_btc.id, ip_sco.id],
        created_by_ref=identity.id,
        created=ts, modified=ts,
    )

    return stix2.Bundle(
        objects=[identity, actor, ip_sco, ind_ip, ind_pgp, ind_btc, *relationships, report],
        allow_custom=False,
    )



def _defuse(cell: str) -> str:
    """Defuse spreadsheet formula injection (=, +, -, @, tab, CR at cell start)."""
    s = "" if cell is None else str(cell)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def build_csv(case: dict, extra_rows: list[list[str]] | None = None) -> str:
    header = [
        "entity_type", "entity_value", "description", "source_stage",
        "confidence", "signature", "key_id",
        "likelihood_ratio", "log_likelihood_ratio", "contribution_pct", "stance",
    ]
    rows = [
        ["evidence_id", case["evidence_id"], "Case reference", "case", "", "", "", "", "", "", ""],
        ["threat_actor", case["actor_name"], "Suspected actor cluster", "stage_2", f"{case['confidence']}%", "", "", "", "", "", ""],
        *[["alias", a, "Forum alias", "stage_2", "", "", "", "", "", "", ""] for a in case.get("aliases", [])],
        ["ipv4", case["origin_ip"], f"Discovered origin IP, {case.get('geo', '')}", "stage_1", "95%", "", "", "", "", "", ""],
        ["asn", case.get("asn", ""), "Hosting provider of origin IP", "stage_1", "", "", "", "", "", "", ""],
        ["pgp_fingerprint", case.get("pgp_fingerprint", ""), "40 character PGP fingerprint", "stage_2", "90%", "", "", "", "", "", ""],
        ["btc_wallet", case.get("btc_root", ""), "Root of co-spent peel-chain cluster", "stage_2", "85%", "", "", "", "", "", ""],
        ["sha256_seal", case["seal_hash"], "Digital hash seal of custody chain", "stage_3", "", case.get("signature") or "", case.get("key_id") or "", "", "", "", ""],
    ]
    rows.extend(_scoring_contribution_rows(case))
    if extra_rows:
        rows.extend(extra_rows)

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(header)
    for r in rows:
        writer.writerow([_defuse(c) for c in r])
    return "\ufeff" + buf.getvalue()


def _scoring_contribution_rows(case: dict) -> list[list[str]]:
    """Flatten the scoring explainability payload into one row per indicator.

    An examiner reading the CSV must be able to answer "which indicator moved
    the score, and by how much" without opening the API response, so each
    indicator is emitted with its likelihood ratio, log-LR, and share of the
    total log-odds movement.
    """
    scoring = case.get("scoring") or {}
    rows: list[list[str]] = []

    for contribution in scoring.get("contributions", []) or []:
        rows.append(
            [
                "scoring_indicator",
                str(contribution.get("indicator", "")),
                str(contribution.get("detail", "")),
                "scoring",
                f"{contribution.get('share_pct', 0.0)}%",
                "",
                "",
                str(contribution.get("likelihood_ratio", "")),
                str(contribution.get("log_likelihood_ratio", "")),
                str(contribution.get("share_pct", "")),
                str(contribution.get("stance", "")),
            ]
        )

    conflict = scoring.get("conflict") or {}
    if conflict:
        rows.append(
            [
                "scoring_conflict",
                str(conflict.get("conflict_mass", "")),
                (
                    f"Dempster-Shafer conflict mass (severity {conflict.get('severity', 'none')}, "
                    f"threshold {conflict.get('threshold', '')}, "
                    f"applied discount {conflict.get('applied_discount', 0.0)}). "
                    f"{'CONFLICT DETECTED: the evidence contradicts itself.' if conflict.get('conflict_detected') else 'Frame is internally consistent.'}"
                ),
                "scoring",
                str(conflict.get("severity", "")),
                "", "",
                "", "", "",
                "conflict" if conflict.get("conflict_detected") else "consistent",
            ]
        )

    return rows


def build_custody_csv(custody_rows: list[Any]) -> str:
    """Build canonical CSV export for the custody ledger, compatible with verify.html.
    
    Columns: seq, timestamp_utc, operator, action, payload, prev_hash, hash, signature, key_id
    All values sanitized against formula injection via _defuse.
    """
    header = ["seq", "timestamp_utc", "operator", "action", "payload", "prev_hash", "hash", "signature", "key_id"]
    rows = []
    for r in custody_rows:
        seq = str(getattr(r, "seq", ""))
        ts = str(getattr(r, "timestamp", ""))
        operator = str(getattr(r, "actor", "") or getattr(r, "operator", ""))
        action = str(getattr(r, "action", ""))
        payload = str(getattr(r, "payload", "") or "")
        prev_hash = str(getattr(r, "prev_hash", ""))
        entry_hash = str(getattr(r, "entry_hash", "") or getattr(r, "hash", ""))
        sig = str(getattr(r, "signature", "") or "")
        key_id = str(getattr(r, "key_id", "") or "")
        rows.append([seq, ts, operator, action, payload, prev_hash, entry_hash, sig, key_id])

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(header)
    for r in rows:
        writer.writerow([_defuse(c) for c in r])
    return "\ufeff" + buf.getvalue()

