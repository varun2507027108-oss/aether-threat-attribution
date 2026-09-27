"""
Pluggable External Anchoring & Periodic Checkpoint Service.

Provides:
- AnchorBase: Base class for custody chain anchoring
- NullAnchor: Writes periodic internal checkpoints to the database every AETHER_CHECKPOINT_INTERVAL entries (default 10)
- RFC3161Anchor: Submits tip hash to external TSA server via RFC 3161, with soft-fail fallback to internal anchor
- get_anchor(): Factory returning the active anchor configured in the environment
"""
import base64
import json
import logging
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Optional

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models import CustodyCheckpoint

logger = logging.getLogger("aether.anchor")


class AnchorBase(ABC):
    def __init__(self, interval: int = 10) -> None:
        self.interval = interval

    def should_checkpoint(self, seq: int) -> bool:
        if self.interval <= 0:
            return False
        return (seq % self.interval) == 0

    @abstractmethod
    def checkpoint(
        self,
        db: Session,
        case_id: int,
        seq: int,
        tip_hash: str,
    ) -> Optional[CustodyCheckpoint]:
        pass


class NullAnchor(AnchorBase):
    """Default anchor: records an internal checkpoint every `interval` entries."""

    def checkpoint(
        self,
        db: Session,
        case_id: int,
        seq: int,
        tip_hash: str,
    ) -> Optional[CustodyCheckpoint]:
        if not self.should_checkpoint(seq):
            return None
        checkpoint = CustodyCheckpoint(
            case_id=case_id,
            seq=seq,
            tip_hash=tip_hash,
            anchor_type="internal",
            anchor_token=None,
        )
        db.add(checkpoint)
        db.commit()
        db.refresh(checkpoint)
        logger.info("Created internal custody checkpoint at seq %d (case %d, tip %s)", seq, case_id, tip_hash[:16])
        return checkpoint


class RFC3161Anchor(AnchorBase):
    """RFC 3161 external Time Stamp Authority (TSA) anchor with graceful soft-fail."""

    def __init__(self, tsa_url: str, interval: int = 10, timeout_seconds: float = 4.0) -> None:
        super().__init__(interval=interval)
        self.tsa_url = tsa_url
        self.timeout_seconds = timeout_seconds

    def _request_tsa_token(self, tip_hash: str) -> Optional[str]:
        """Send hash to TSA. Fails soft if unreachable."""
        payload = json.dumps({"hash": tip_hash, "algorithm": "sha256"}).encode("utf-8")
        req = urllib.request.Request(
            self.tsa_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AETHER-Forensic-Attribution/2.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                data = resp.read()
                return base64.b64encode(data).decode("ascii")
        except Exception as e:
            logger.warning("TSA endpoint %s error: %s. Soft-failing to internal checkpoint.", self.tsa_url, e)
            return None

    def checkpoint(
        self,
        db: Session,
        case_id: int,
        seq: int,
        tip_hash: str,
    ) -> Optional[CustodyCheckpoint]:
        if not self.should_checkpoint(seq):
            return None
        anchor_token = self._request_tsa_token(tip_hash)
        anchor_type = "rfc3161" if anchor_token else "internal"

        checkpoint = CustodyCheckpoint(
            case_id=case_id,
            seq=seq,
            tip_hash=tip_hash,
            anchor_type=anchor_type,
            anchor_token=anchor_token,
        )
        db.add(checkpoint)
        db.commit()
        db.refresh(checkpoint)
        logger.info(
            "Created %s custody checkpoint at seq %d (case %d, tip %s)",
            anchor_type, seq, case_id, tip_hash[:16],
        )
        return checkpoint


def get_anchor() -> AnchorBase:
    interval_str = os.getenv("AETHER_CHECKPOINT_INTERVAL", "10")
    try:
        interval = int(interval_str)
    except ValueError:
        interval = 10

    tsa_url = os.getenv("AETHER_TSA_URL", "").strip()
    if tsa_url:
        return RFC3161Anchor(tsa_url=tsa_url, interval=interval)
    return NullAnchor(interval=interval)


def checkpoint_if_needed(
    db: Session,
    case_id: int,
    seq: int,
    tip_hash: str,
) -> Optional[CustodyCheckpoint]:
    anchor = get_anchor()
    if anchor.should_checkpoint(seq):
        return anchor.checkpoint(db, case_id, seq, tip_hash)
    return None


def get_last_checkpoint(db: Session, case_id: int) -> Optional[CustodyCheckpoint]:
    return db.execute(
        select(CustodyCheckpoint)
        .where(CustodyCheckpoint.case_id == case_id)
        .order_by(desc(CustodyCheckpoint.seq))
    ).scalars().first()
