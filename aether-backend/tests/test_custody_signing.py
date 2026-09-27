"""Tests for Phase 2: Signed custody chain and external anchoring.

Verifies:
1. Canonical serialization and Ed25519 signature generation.
2. Recompute attack defeat: Attacker modifying row k and recomputing SHA-256
   for k..n passes hash verification (hash_ok=True) but fails signature verification
   (signature_ok=False), failing overall verification.
3. Naive tamper detection: Single row modification breaks hash chain at broken_at_seq.
4. Legacy unsigned entry support (signature=None).
5. External/internal anchoring via NullAnchor and RFC3161 soft-fail behavior.
6. Case custody verification endpoint and custody CSV export.
"""

import base64
import csv
import io
import json
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.models import Case, CustodyCheckpoint, CustodyRow
from app.services.anchor import NullAnchor, RFC3161Anchor, checkpoint_if_needed, get_last_checkpoint
from app.services.custody import (
    GENESIS_HASH,
    CustodyChain,
    CustodyEntry,
    canonical_bytes,
    compute_key_id,
    sign_canonical,
    verify_signature,
)


@pytest.fixture
def signing_keys():
    """Generates an ephemeral Ed25519 keypair for testing."""
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv_b64, pub_b64, priv, pub


def test_canonical_bytes_deterministic():
    """Canonical serialization must be strictly reproducible and sorted."""
    b1 = canonical_bytes(1, "2026-09-27T12:00:00Z", operator="Analyst-1", action="EVIDENCE_INGESTED", entry_hash="abc123hash")
    b2 = canonical_bytes(1, "2026-09-27T12:00:00Z", actor="Analyst-1", action="EVIDENCE_INGESTED", entry_hash="abc123hash")
    assert b1 == b2
    parsed = json.loads(b1.decode("utf-8"))
    assert parsed["seq"] == 1
    assert parsed["timestamp"] == "2026-09-27T12:00:00Z"
    assert parsed["operator"] == "Analyst-1"
    assert parsed["action"] == "EVIDENCE_INGESTED"
    assert parsed["entry_hash"] == "abc123hash"


def test_ed25519_sign_and_verify(signing_keys):
    priv_b64, pub_b64, _, _ = signing_keys
    data = b"test payload for signing"
    sig, key_id = sign_canonical(data, priv_b64)
    assert sig is not None
    assert len(sig) > 0
    assert key_id.startswith("ed25519:")

    assert verify_signature(data, sig, pub_b64) is True
    # Tampered data should fail signature verification
    assert verify_signature(b"tampered payload", sig, pub_b64) is False


def test_signed_custody_chain_append_and_verify(signing_keys, monkeypatch):
    priv_b64, pub_b64, _, _ = signing_keys
    monkeypatch.setenv("AETHER_SIGNING_KEY", priv_b64)
    monkeypatch.setenv("AETHER_SIGNING_PUBLIC_KEY", pub_b64)

    chain = CustodyChain()
    e1 = chain.append(actor="Officer Alice", action="Case initialized")
    e2 = chain.append(actor="AETHER Recon", action="Domain recon completed")
    e3 = chain.append(actor="AETHER Scoring", action="Attribution scored")

    assert e1.signature is not None
    assert e2.signature is not None
    assert e3.signature is not None
    assert e1.key_id == compute_key_id(pub_b64)

    res = chain.verify()
    assert res.valid is True
    assert res.broken_at_seq is None
    assert res.hash_ok is True
    assert res.signature_ok is True
    assert res.signed_count == 3
    assert res.total_count == 3


def test_recompute_attack_detected(signing_keys, monkeypatch):
    """CRITICAL TEST: Recompute attack.

    An attacker with database write access modifies row k, then correctly
    recomputes the SHA-256 hashes for all subsequent rows k..n.
    Under pure hash chaining, this attack would pass undetected.
    With Ed25519 signature enforcement, the hash chain is intact (hash_ok=True)
    but signature verification FAILS (signature_ok=False), rejecting the chain.
    """
    priv_b64, pub_b64, _, _ = signing_keys
    monkeypatch.setenv("AETHER_SIGNING_KEY", priv_b64)
    monkeypatch.setenv("AETHER_SIGNING_PUBLIC_KEY", pub_b64)

    # 1. Honest investigator creates a 4-entry signed chain
    chain = CustodyChain()
    chain.append(actor="Officer 1", action="Genesis evidence created")
    chain.append(actor="Officer 1", action="Target IP 185.220.101.42 confirmed")
    chain.append(actor="Analyst 2", action="Attribution assigned to APT-Dark")
    chain.append(actor="Lead Officer", action="Certificate generated")

    # Serialize to database-like rows
    rows = [
        {
            "seq": e.seq,
            "timestamp": e.timestamp,
            "actor": e.actor,
            "action": e.action,
            "prev_hash": e.prev_hash,
            "entry_hash": e.entry_hash,
            "signature": e.signature,
            "key_id": e.key_id,
        }
        for e in chain.entries
    ]

    # Verify honest chain passes
    honest_chain = CustodyChain.from_rows(rows)
    honest_res = honest_chain.verify()
    assert honest_res.valid is True
    assert honest_res.hash_ok is True
    assert honest_res.signature_ok is True

    # 2. Malicious attacker modifies row 2 (seq=2) to exonerate suspect
    rows[1]["action"] = "Target IP exonerated: benign exit node"

    # Attacker recomputes hashes for row 2..4 to bypass hash-chain checks
    for i in range(1, len(rows)):
        curr = rows[i]
        curr["prev_hash"] = rows[i - 1]["entry_hash"] if i > 0 else GENESIS_HASH
        # Attacker recalculates SHA-256 matching CustodyEntry hashing formula
        dummy_entry = CustodyEntry(
            seq=curr["seq"],
            timestamp=curr["timestamp"],
            actor=curr["actor"],
            action=curr["action"],
            prev_hash=curr["prev_hash"],
        )
        curr["entry_hash"] = dummy_entry.entry_hash
        # Attacker does NOT possess the private key, so they cannot sign the new hash!

    # 3. Verify tampered chain
    tampered_chain = CustodyChain.from_rows(rows)
    tampered_res = tampered_chain.verify()

    # The hash linkages are mathematically valid because attacker recomputed them!
    assert tampered_res.hash_ok is True, "Hash chain should appear valid after recomputation"

    # BUT signature verification MUST FAIL!
    assert tampered_res.signature_ok is False, "Signature verification MUST fail under recompute attack"
    assert tampered_res.valid is False, "Overall chain validity MUST be False"
    assert tampered_res.failure_layer == "signature"
    assert tampered_res.broken_at_seq == 2


def test_naive_tamper_detected(signing_keys, monkeypatch):
    """Naive tamper: modifying one row without recomputing subsequent hashes."""
    priv_b64, pub_b64, _, _ = signing_keys
    monkeypatch.setenv("AETHER_SIGNING_KEY", priv_b64)
    monkeypatch.setenv("AETHER_SIGNING_PUBLIC_KEY", pub_b64)

    chain = CustodyChain()
    chain.append(actor="Analyst", action="Row 1")
    chain.append(actor="Analyst", action="Row 2")
    chain.append(actor="Analyst", action="Row 3")

    rows = [
        {
            "seq": e.seq,
            "timestamp": e.timestamp,
            "actor": e.actor,
            "action": e.action,
            "prev_hash": e.prev_hash,
            "entry_hash": e.entry_hash,
            "signature": e.signature,
            "key_id": e.key_id,
        }
        for e in chain.entries
    ]

    # Tamper with row 2 without rehashing
    rows[1]["action"] = "Tampered action"

    tampered_chain = CustodyChain.from_rows(rows)
    res = tampered_chain.verify()
    assert res.valid is False
    assert res.hash_ok is False
    assert res.broken_at_seq == 2


def test_legacy_unsigned_entries_backward_compatible():
    """Legacy entries without signatures should remain valid if hash chain intact."""
    chain = CustodyChain()
    e1 = chain.append(actor="Legacy", action="Legacy row 1")
    e2 = chain.append(actor="Legacy", action="Legacy row 2")

    assert e1.signature is None
    assert e2.signature is None

    res = chain.verify()
    assert res.valid is True
    assert res.hash_ok is True
    assert res.signature_ok is True
    assert res.signed_count == 0


def test_null_anchor_checkpointing(db_session, monkeypatch):
    """NullAnchor writes an internal checkpoint every AETHER_CHECKPOINT_INTERVAL entries."""
    case = Case(
        evidence_id="AT-2026-CHKP",
        actor_name="Checkpoint Actor",
        origin_ip="185.220.101.42",
        geo="Munich, Germany",
        asn="AS16276",
        confidence=80.0,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    anchor = NullAnchor(interval=5)

    # seq 1..4 -> no checkpoint
    for s in range(1, 5):
        cp = anchor.checkpoint(db_session, case.id, s, f"hash_{s}")
        assert cp is None

    # seq 5 -> checkpoint triggered
    cp5 = anchor.checkpoint(db_session, case.id, 5, "hash_5")
    assert cp5 is not None
    assert cp5.seq == 5
    assert cp5.anchor_type == "internal"
    assert cp5.tip_hash == "hash_5"

    last = get_last_checkpoint(db_session, case.id)
    assert last is not None
    assert last.seq == 5


def test_rfc3161_anchor_soft_fail(db_session, monkeypatch):
    """RFC3161Anchor must fail soft and fall back to 'internal' when TSA is unreachable."""
    anchor = RFC3161Anchor(tsa_url="http://127.0.0.1:54321/unreachable-tsa", interval=1)

    case = Case(
        evidence_id="AT-2026-TSA0",
        actor_name="TSA Actor",
        origin_ip="185.220.101.42",
        geo="Munich, Germany",
        asn="AS16276",
        confidence=75.0,
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)

    # Should NOT raise an exception; must log warning and downgrade to internal
    cp = anchor.checkpoint(db_session, case.id, 1, "tip_hash_abc")
    assert cp is not None
    assert cp.anchor_type == "internal"
    assert cp.tip_hash == "tip_hash_abc"


def test_api_verify_custody_and_export(client, signing_keys, monkeypatch):
    """Test /api/cases/{id}/verify returns rich verification metadata and custody export works."""
    priv_b64, pub_b64, _, _ = signing_keys
    monkeypatch.setenv("AETHER_SIGNING_KEY", priv_b64)
    monkeypatch.setenv("AETHER_SIGNING_PUBLIC_KEY", pub_b64)

    # Create case
    case_payload = {
        "evidence_id": "AT-2026-CUST",
        "actor_name": "Custody Test Actor",
        "aliases": ["SignTester"],
        "origin_ip": "185.220.101.42",
        "geo": "Germany",
        "asn": "AS16276",
        "confidence": 85.0,
    }
    r = client.post("/api/cases", json=case_payload)
    assert r.status_code == 201

    # Add custody entry
    r_entry = client.post(
        "/api/cases/AT-2026-CUST/custody",
        json={"actor": "Lead Analyst", "action": "Signed evidence log entry"},
    )
    assert r_entry.status_code == 201
    entry_data = r_entry.json()
    assert entry_data["signature"] is not None
    assert entry_data["signed"] is True

    # Verify custody endpoint
    r_verif = client.get("/api/cases/AT-2026-CUST/verify")
    assert r_verif.status_code == 200
    verif_data = r_verif.json()
    assert verif_data["valid"] is True
    assert verif_data["hash_ok"] is True
    assert verif_data["signature_ok"] is True
    assert verif_data["signed_count"] >= 1

    # Export custody CSV
    r_csv = client.get("/api/cases/AT-2026-CUST/export/custody")
    assert r_csv.status_code == 200
    assert "aether_custody_ledger_AT-2026-CUST.csv" in r_csv.headers["content-disposition"]
    csv_text = r_csv.text.lstrip("\ufeff")
    reader = list(csv.reader(io.StringIO(csv_text)))
    header = reader[0]
    assert header == ["seq", "timestamp_utc", "operator", "action", "payload", "prev_hash", "hash", "signature", "key_id"]
    assert len(reader) >= 2  # header + added entry
