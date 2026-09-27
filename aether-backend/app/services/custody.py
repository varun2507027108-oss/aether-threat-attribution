"""
Tamper-evident chain of custody with Ed25519 cryptographic signing.

Each ledger entry is hashed together with the hash of the entry before it
(a Merkle-style hash chain, the same idea git commits and blockchains use).
Changing, reordering, or deleting any past entry breaks every hash after it,
so verification is a single linear walk that either matches or doesn't.

In Phase 2, each entry can also be digitally signed using an Ed25519 private key
(AETHER_SIGNING_KEY) over canonical serialization: canonical_bytes().
This defeats the 'recompute attack' where an attacker with DB write access
modifies entry k and recomputes hashes for k..n.

If no signing key is configured (zero-Docker default dev path), entries remain
unsigned legacy entries, which verify cleanly if the hash chain is intact.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

logger = logging.getLogger("aether.custody")

GENESIS_HASH = "0" * 64


def _canonical(obj: dict) -> bytes:
    """Deterministic JSON encoding so the same entry always hashes the same way."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_bytes(
    seq: int,
    timestamp: str,
    operator: str | None = None,
    action: str = "",
    entry_hash: str = "",
    actor: str | None = None,
) -> bytes:
    """Canonical UTF-8 JSON serialization of an entry for cryptographic signing.
    Accepts operator or actor (synonymous).
    Sorts keys deterministically with no whitespace."""
    op = operator if operator is not None else (actor or "")
    payload = {
        "action": str(action),
        "entry_hash": str(entry_hash),
        "operator": str(op),
        "seq": int(seq),
        "timestamp": str(timestamp),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def get_signing_private_key(key_b64: Optional[str] = None) -> Optional[ed25519.Ed25519PrivateKey]:
    raw = key_b64 or os.getenv("AETHER_SIGNING_KEY", "").strip()
    if not raw:
        return None
    try:
        key_bytes = base64.b64decode(raw)
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
    except Exception as e:
        logger.error("Failed to parse AETHER_SIGNING_KEY: %s", e)
        return None


def get_signing_public_key(pub_b64: Optional[str] = None) -> Optional[ed25519.Ed25519PublicKey]:
    raw = pub_b64 or os.getenv("AETHER_SIGNING_PUBLIC_KEY", "").strip()
    if raw:
        try:
            pub_bytes = base64.b64decode(raw)
            return ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as e:
            logger.error("Failed to parse AETHER_SIGNING_PUBLIC_KEY: %s", e)
    # If public key not explicitly set, try deriving from private key
    priv = get_signing_private_key()
    if priv is not None:
        return priv.public_key()
    return None


def compute_key_id(public_key: ed25519.Ed25519PublicKey | str) -> str:
    if isinstance(public_key, str):
        pub = get_signing_public_key(public_key)
        if pub is None:
            return ""
        public_key = pub
    pub_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    digest = hashlib.sha256(pub_raw).hexdigest()
    return f"ed25519:{digest[:16]}"


def sign_canonical(
    canonical_data: bytes,
    private_key: Optional[ed25519.Ed25519PrivateKey | str] = None,
) -> tuple[Optional[str], Optional[str]]:
    if isinstance(private_key, str):
        key = get_signing_private_key(private_key)
    else:
        key = private_key or get_signing_private_key()
    if key is None:
        return None, None
    sig_bytes = key.sign(canonical_data)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    key_id = compute_key_id(key.public_key())
    return sig_b64, key_id


def verify_signature(
    canonical_data: bytes,
    signature_b64: str,
    public_key: Optional[ed25519.Ed25519PublicKey | str] = None,
) -> bool:
    if isinstance(public_key, str):
        pub = get_signing_public_key(public_key)
    else:
        pub = public_key or get_signing_public_key()
    if pub is None:
        return True
    try:
        sig_bytes = base64.b64decode(signature_b64)
        pub.verify(sig_bytes, canonical_data)
        return True
    except (InvalidSignature, Exception):
        return False


class ChainVerifyResult(tuple):
    """2-tuple (valid, broken_at_seq) subclass with rich metadata attributes for backward compatibility."""

    def __new__(
        cls,
        valid: bool,
        broken_at_seq: int | None,
        hash_ok: bool,
        signature_ok: bool,
        failure_layer: str | None,
        signed_count: int,
        total_count: int,
    ):
        instance = super().__new__(cls, (valid, broken_at_seq))
        instance.valid = valid
        instance.broken_at_seq = broken_at_seq
        instance.hash_ok = hash_ok
        instance.signature_ok = signature_ok
        instance.failure_layer = failure_layer
        instance.signed_count = signed_count
        instance.total_count = total_count
        return instance

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "broken_at_seq": self.broken_at_seq,
            "hash_ok": self.hash_ok,
            "signature_ok": self.signature_ok,
            "failure_layer": self.failure_layer,
            "signed_count": self.signed_count,
            "total_count": self.total_count,
        }


@dataclass
class CustodyEntry:
    seq: int
    timestamp: str
    actor: str
    action: str
    prev_hash: str
    entry_hash: str = field(init=False)
    signature: Optional[str] = None
    key_id: Optional[str] = None

    def __post_init__(self) -> None:
        payload = {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "prev_hash": self.prev_hash,
        }
        self.entry_hash = hashlib.sha256(_canonical(payload)).hexdigest()
        # Sign canonical bytes if AETHER_SIGNING_KEY is configured and signature not already set
        if self.signature is None and get_signing_private_key() is not None:
            cbytes = canonical_bytes(self.seq, self.timestamp, self.actor, self.action, self.entry_hash)
            sig, kid = sign_canonical(cbytes)
            self.signature = sig
            self.key_id = kid

    def to_dict(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "key_id": self.key_id,
        }


class CustodyChain:
    """In-memory hash chain builder. The API layer persists entries to SQLite/Postgres
    and rebuilds / verifies this chain from the stored rows."""

    def __init__(self) -> None:
        self.entries: list[CustodyEntry] = []

    def append(
        self,
        actor: str,
        action: str,
        timestamp: Optional[str] = None,
        signature: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> CustodyEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
        entry = CustodyEntry(
            seq=len(self.entries) + 1,
            timestamp=timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            actor=actor,
            action=action,
            prev_hash=prev_hash,
            signature=signature,
            key_id=key_id,
        )
        self.entries.append(entry)
        return entry

    def verify(self, public_key_b64: Optional[str] = None) -> ChainVerifyResult:
        """Returns ChainVerifyResult(valid, broken_at_seq, hash_ok, signature_ok, failure_layer, signed_count, total_count).
        Unpacks cleanly into (valid, broken_at) for 100% backward compatibility."""
        pub_key = get_signing_public_key(public_key_b64)
        prev_hash = GENESIS_HASH
        hash_ok = True
        signature_ok = True
        first_broken_seq: Optional[int] = None
        failure_layer: Optional[str] = None
        signed_count = 0

        for e in self.entries:
            # 1. Check hash linkage
            if e.prev_hash != prev_hash:
                hash_ok = False
                if first_broken_seq is None:
                    first_broken_seq = e.seq
                    failure_layer = "hash_chain"

            recomputed = hashlib.sha256(_canonical({
                "seq": e.seq,
                "timestamp": e.timestamp,
                "actor": e.actor,
                "action": e.action,
                "prev_hash": e.prev_hash,
            })).hexdigest()
            if recomputed != e.entry_hash:
                hash_ok = False
                if first_broken_seq is None:
                    first_broken_seq = e.seq
                    failure_layer = "hash_chain"

            # 2. Check digital signature if entry is signed
            if e.signature is not None:
                signed_count += 1
                cbytes = canonical_bytes(e.seq, e.timestamp, e.actor, e.action, e.entry_hash)
                if pub_key is not None:
                    if not verify_signature(cbytes, e.signature, pub_key):
                        signature_ok = False
                        if first_broken_seq is None:
                            first_broken_seq = e.seq
                            failure_layer = "signature"
                        elif failure_layer == "hash_chain":
                            failure_layer = "hash_chain+signature"
            else:
                # Unsigned legacy entry: valid if hash chain intact
                pass

            prev_hash = e.entry_hash

        valid = hash_ok and signature_ok
        return ChainVerifyResult(
            valid=valid,
            broken_at_seq=first_broken_seq,
            hash_ok=hash_ok,
            signature_ok=signature_ok,
            failure_layer=failure_layer,
            signed_count=signed_count,
            total_count=len(self.entries),
        )

    @classmethod
    def from_rows(cls, rows: list[dict]) -> "CustodyChain":
        """Rebuild a chain from stored rows without re-deriving hashes,
        so verify() can detect if a row was edited at rest."""
        chain = cls()
        for r in rows:
            e = CustodyEntry.__new__(CustodyEntry)
            e.seq = r["seq"]
            e.timestamp = r["timestamp"]
            e.actor = r["actor"]
            e.action = r["action"]
            e.prev_hash = r["prev_hash"]
            e.entry_hash = r["entry_hash"]  # stored hash, NOT recomputed here
            e.signature = r.get("signature")
            e.key_id = r.get("key_id")
            chain.entries.append(e)
        return chain

    def seal(self) -> str:
        """Digital hash seal over the entire chain: sha256 of the final entry's
        hash concatenated with the chain length. Placed on the dossier."""
        if not self.entries:
            return hashlib.sha256(GENESIS_HASH.encode()).hexdigest()
        tip = self.entries[-1].entry_hash
        return hashlib.sha256(f"{tip}:{len(self.entries)}".encode()).hexdigest()
