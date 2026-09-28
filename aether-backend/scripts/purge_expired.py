"""DPDP Act 2023 retention governor for Project AETHER.

Purges cases past the retention window and records the purge itself in a
case-independent custody chain, so proof of what was destroyed outlives the
destruction.

Dry-run by default. A purge is irreversible.

Usage:
    python scripts/purge_expired.py                  # dry run, report only
    python scripts/purge_expired.py --commit         # execute the purge
    python scripts/purge_expired.py --retention-days 30
    python scripts/purge_expired.py --verify-chain    # verify the purge chain
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.db import SessionLocal  # noqa: E402
from app.services.governance import (  # noqa: E402
    get_retention_days,
    purge_expired_cases,
    verify_purge_chain,
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Purge cases past the DPDP retention window.")
    parser.add_argument("--commit", action="store_true",
                        help="Actually delete. Omit for a dry-run report.")
    parser.add_argument("--retention-days", type=int, default=None,
                        help=f"Override AETHER_RETENTION_DAYS (default {get_retention_days()}).")
    parser.add_argument("--verify-chain", action="store_true",
                        help="Verify the case-independent purge custody chain and exit.")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    args = parser.parse_args(argv)

    db = SessionLocal()
    try:
        if args.verify_chain:
            status = verify_purge_chain(db)
            if args.json:
                print(json.dumps(status, indent=2))
            else:
                print("Purge chain")
                print("-" * 60)
                print(f"valid        : {status['valid']}")
                print(f"entry count  : {status['entry_count']}")
                print(f"seal         : {status['seal']}")
            return 0 if status["valid"] else 1

        result = purge_expired_cases(
            db,
            commit=args.commit,
            retention_days=args.retention_days,
        )
    finally:
        db.close()

    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    mode = result["mode"]
    print("=" * 70)
    print(f"AETHER retention governor ({mode.upper()} MODE)")
    print("=" * 70)
    print(f"retention window : {result['retention_days']} days")
    print(f"operator         : {result['operator']}")
    print(f"timestamp        : {result['timestamp']}")
    print(f"cases expired    : {len(result['cases'])}")
    print(f"manifest hash    : {result['manifest_hash']}")
    print()

    if result["cases"]:
        print(f"{'evidence_id':<24} {'created':<28} custody/evidence")
        print("-" * 70)
        for case in result["cases"]:
            contents = case["contents"]
            print(
                f"{case['evidence_id']:<24} {str(case['created_at']):<28} "
                f"{contents['custody_entries']}/{contents['evidence_records']}"
            )
        print()

    if mode == "commit":
        print(f"PURGED {result['purged_count']} case(s): {result['purged_case_ids']}")
        entry = result.get("purge_custody_entry")
        if entry:
            print(f"purge custody entry: seq={entry['seq']} hash={entry['entry_hash']}")
        print(result["note"])
    else:
        print("DRY RUN - nothing was deleted.")
        print(result["note"])

    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
