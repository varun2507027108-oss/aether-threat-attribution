"""Stylometry validation harness for Project AETHER.

Sweeps the reporting threshold over the labelled author corpus in
``docs/validation/stylometry_corpus.json`` and reports ROC, AUC, and the false
positive rate at each candidate threshold. Writes ``docs/stylometry/report.md``.

The task is framed as author verification, which is what the engine is used for:

  * positives   -- two samples by the same author
  * negatives   -- two samples by different authors, including the adjacent-
                   register pairs (B vs D are both formal English) that a naive
                   cosine classifier confuses

Usage:
    python scripts/validate_stylometry.py
    python scripts/validate_stylometry.py --corpus path.json --report out.md
    python scripts/validate_stylometry.py --sweep           # per-threshold table
    python scripts/validate_stylometry.py --check-threshold 0.72  # CI assertion
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.stylometry import (  # noqa: E402
    DEFAULT_BURROWS_REFERENCE,
    DEFAULT_ENSEMBLE_WEIGHTS,
    DEFAULT_STYLOMETRY_FPR,
    DEFAULT_STYLOMETRY_THRESHOLD,
    analyze_stylometry,
    script_profile,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
DEFAULT_CORPUS = REPO_ROOT / "docs" / "validation" / "stylometry_corpus.json"
DEFAULT_REPORT = REPO_ROOT / "docs" / "stylometry" / "report.md"

TARGET_FPR = 0.05


# --------------------------------------------------------------------------- #
# Corpus handling
# --------------------------------------------------------------------------- #

def load_corpus(path: Path) -> Dict[str, List[str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    authors = payload.get("authors", {})
    if len(authors) < 2:
        raise SystemExit(f"{path} must define at least two authors")
    corpus: Dict[str, List[str]] = {}
    for author, entry in authors.items():
        samples = entry.get("samples") if isinstance(entry, dict) else entry
        if not samples or len(samples) < 2:
            raise SystemExit(f"author {author} needs at least two samples")
        corpus[author] = list(samples)
    return corpus


def build_pairs(corpus: Dict[str, List[str]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Enumerate every same-author and cross-author comparison."""
    positives: List[Dict[str, Any]] = []
    negatives: List[Dict[str, Any]] = []

    authors = sorted(corpus)
    for author in authors:
        for i, j in itertools.combinations(range(len(corpus[author])), 2):
            positives.append({
                "label": 1,
                "author": author,
                "pair": (i, j),
                "text_a": corpus[author][i],
                "text_b": corpus[author][j],
            })

    for author_a, author_b in itertools.combinations(authors, 2):
        for i, j in itertools.product(range(len(corpus[author_a])), range(len(corpus[author_b]))):
            negatives.append({
                "label": 0,
                "author": f"{author_a}|{author_b}",
                "pair": (i, j),
                "text_a": corpus[author_a][i],
                "text_b": corpus[author_b][j],
            })

    return positives, negatives


def score_pairs(
    pairs: Sequence[Dict[str, Any]],
    method: str = "ensemble",
    weights: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """Score each pair with the chosen aggregation method."""
    scored: List[Dict[str, Any]] = []
    for pair in pairs:
        result = analyze_stylometry(pair["text_a"], pair["text_b"], weights=weights)
        if method == "cosine":
            score = result["legacy_cosine_composite"]
        elif method == "ensemble":
            score = result["similarity_score"]
        elif method == "delta":
            score = result["method_scores"]["delta"].get("similarity")
        elif method == "ncd":
            score = result["method_scores"]["ncd"].get("similarity")
        else:
            raise SystemExit(f"unknown method {method!r}")

        scored.append({
            "label": pair["label"],
            "author": pair["author"],
            "pair": pair["pair"],
            "score": score,
            "methods_used": result["ensemble"]["methods_used"],
            "degraded": result["ensemble"]["degraded"],
        })
    return scored


# --------------------------------------------------------------------------- #
# Metrics
# --------------------------------------------------------------------------- #

def roc_points(scored: Sequence[Dict[str, Any]]) -> List[Tuple[float, float]]:
    """ROC curve as (false positive rate, true positive rate) at every cut."""
    usable = [row for row in scored if row["score"] is not None]
    positives = [r for r in usable if r["label"] == 1]
    negatives = [r for r in usable if r["label"] == 0]
    if not positives or not negatives:
        return []

    cuts = sorted({r["score"] for r in usable}, reverse=True)
    points = [(0.0, 0.0)]
    for cut in cuts:
        tpr = sum(1 for r in positives if r["score"] >= cut) / len(positives)
        fpr = sum(1 for r in negatives if r["score"] >= cut) / len(negatives)
        points.append((round(fpr, 6), round(tpr, 6)))
    points.append((1.0, 1.0))
    return points


def auc(scored: Sequence[Dict[str, Any]]) -> float:
    """Mann-Whitney U AUC with tie handling."""
    usable = [row for row in scored if row["score"] is not None]
    positives = [r["score"] for r in usable if r["label"] == 1]
    negatives = [r["score"] for r in usable if r["label"] == 0]
    if not positives or not negatives:
        return float("nan")

    wins = 0.0
    for p in positives:
        for n in negatives:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def rates_at(scored: Sequence[Dict[str, Any]], threshold: float) -> Dict[str, Any]:
    usable = [row for row in scored if row["score"] is not None]
    positives = [r for r in usable if r["label"] == 1]
    negatives = [r for r in usable if r["label"] == 0]
    if not positives or not negatives:
        return {"threshold": threshold, "fpr": float("nan"), "tpr": float("nan"), "fp": 0, "fn": 0, "tp": 0, "tn": 0}

    tp = sum(1 for r in positives if r["score"] >= threshold)
    fn = len(positives) - tp
    fp = sum(1 for r in negatives if r["score"] >= threshold)
    tn = len(negatives) - fp
    return {
        "threshold": threshold,
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "fpr": round(fp / len(negatives), 6),
        "tpr": round(tp / len(positives), 6),
    }


def best_threshold_for_fpr(scored: Sequence[Dict[str, Any]], target_fpr: float = TARGET_FPR) -> Optional[float]:
    """Highest threshold whose FPR is at or below the target, maximizing TPR.

    Scanning downward from 1.0 finds the most permissive cut that still honours
    the false-positive budget, which is what an examiner wants: do not miss a
    real lead, but never accuse the wrong author.
    """
    usable = [row for row in scored if row["score"] is not None]
    if not usable:
        return None
    candidates = sorted({r["score"] for r in usable}, reverse=True)
    best: Optional[Tuple[float, float]] = None
    for cut in candidates:
        stats = rates_at(scored, cut)
        if stats["fpr"] <= target_fpr:
            if best is None or stats["tpr"] > best[1]:
                best = (cut, stats["tpr"])
    return round(best[0], 4) if best else None


def worst_false_positives(scored: Sequence[Dict[str, Any]], threshold: float, limit: int = 5) -> List[Dict[str, Any]]:
    """The cross-author pairs that scored highest; these are the method's blind spots."""
    negatives = [r for r in scored if r["label"] == 0 and r["score"] is not None]
    negatives.sort(key=lambda r: r["score"], reverse=True)
    return [
        {"author": r["author"], "pair": r["pair"], "score": r["score"], "above_threshold": r["score"] >= threshold}
        for r in negatives[:limit]
    ]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_report(
    corpus_path: Path,
    scored: Dict[str, List[Dict[str, Any]]],
    shipped: Dict[str, Any],
) -> str:
    lines: List[str] = []
    lines.append("# Stylometry Validation Report")
    lines.append("")
    lines.append(f"Corpus: `{corpus_path}`")
    lines.append("")
    lines.append("## Corpus")
    lines.append("")
    lines.append("| Author | Register | Samples | Script mix |")
    lines.append("|---|---|---|---|")
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    for author, entry in corpus["authors"].items():
        samples = entry["samples"]
        profile = script_profile(" ".join(samples))
        script_mix = f"latin {profile['latin']:.2f}, indic {profile['indic']:.2f}, emoji {profile['emoji']:.2f}"
        lines.append(f"| {author} | {entry['profile']} | {len(samples)} | {script_mix} |")
    lines.append("")

    lines.append("## Method comparison")
    lines.append("")
    lines.append("| Aggregation | AUC | FPR @ shipped | TPR @ shipped |")
    lines.append("|---|---|---|---|")
    for method in ("cosine", "ensemble"):
        rows = scored[method]
        stats = rates_at(rows, shipped["threshold"])
        lines.append(
            f"| {method} | {auc(rows):.4f} | {stats['fpr']:.4f} | {stats['tpr']:.4f} |"
        )
    lines.append("")

    lines.append("## ROC")
    lines.append("")
    lines.append("| FPR | TPR |")
    lines.append("|---|---|")
    for fpr, tpr in roc_points(scored["ensemble"]):
        lines.append(f"| {fpr:.3f} | {tpr:.3f} |")
    lines.append("")

    lines.append("## Threshold")
    lines.append("")
    lines.append(f"- Shipped threshold: **{shipped['threshold']}**")
    lines.append(f"- Measured FPR at shipped threshold: **{shipped['fpr']:.4f}** (target <= {TARGET_FPR})")
    lines.append(f"- TPR at shipped threshold: **{shipped['tpr']:.4f}**")
    lines.append(f"- Recommended threshold for FPR <= {TARGET_FPR}: **{shipped['recommended']}**")
    lines.append(f"- Ensemble weights: `{shipped['weights']}`")
    lines.append(f"- Burrows' Delta reference documents: {len(DEFAULT_BURROWS_REFERENCE)}")
    lines.append("")

    lines.append("## Highest-scoring cross-author pairs (the method's blind spots)")
    lines.append("")
    lines.append("| Authors | Sample pair | Score | Above threshold |")
    lines.append("|---|---|---|---|")
    for entry in shipped["worst_false_positives"]:
        lines.append(
            f"| {entry['author']} | {entry['pair'][0]} vs {entry['pair'][1]} | "
            f"{entry['score']:.4f} | {'YES' if entry['above_threshold'] else 'no'} |"
        )
    lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "These are synthetic authors, so the absolute numbers characterise the *method* on a "
        "controlled corpus, not any real writer. The corpus deliberately includes two "
        "adjacent-register pairs (formal English vs. formal English) that a pure cosine "
        "classifier confuses, which is the honest failure mode for a darknet context where "
        "most notes share a genre."
    )
    lines.append("")
    lines.append(
        "A false positive here means naming the wrong person in a court filing. That is why "
        "the default threshold is set from an FPR budget rather than from maximum accuracy, "
        "and why the pipeline treats stylometry as a lead that must be corroborated by a "
        "deterministic artefact."
    )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the AETHER stylometry ensemble.")
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--threshold", type=float, default=DEFAULT_STYLOMETRY_THRESHOLD)
    parser.add_argument("--check-threshold", type=float, default=None,
                        help="exit non-zero if the FPR at this threshold exceeds the target")
    parser.add_argument("--sweep", action="store_true", help="print every candidate threshold")
    parser.add_argument("--no-report", action="store_true", help="skip writing the markdown report")
    args = parser.parse_args(argv)

    if not args.corpus.exists():
        print(f"error: corpus not found: {args.corpus}", file=sys.stderr)
        return 2

    corpus = load_corpus(args.corpus)
    positives, negatives = build_pairs(corpus)

    print("=" * 78)
    print("AETHER stylometry validation")
    print("=" * 78)
    print(f"corpus           : {args.corpus}")
    print(f"authors          : {len(corpus)}")
    print(f"same-author pairs: {len(positives)}")
    print(f"cross-author pairs: {len(negatives)}")
    print()

    scored = {
        "cosine": score_pairs(positives + negatives, method="cosine"),
        "ensemble": score_pairs(positives + negatives, method="ensemble"),
    }

    shipped = {
        "threshold": args.threshold,
        "fpr": rates_at(scored["ensemble"], args.threshold)["fpr"],
        "tpr": rates_at(scored["ensemble"], args.threshold)["tpr"],
        "recommended": best_threshold_for_fpr(scored["ensemble"]),
        "weights": DEFAULT_ENSEMBLE_WEIGHTS,
        "worst_false_positives": worst_false_positives(scored["ensemble"], args.threshold),
    }

    print("Results")
    print("-" * 78)
    for method in ("cosine", "ensemble"):
        stats = rates_at(scored[method], args.threshold)
        print(
            f"{method:9} AUC={auc(scored[method]):.4f}  "
            f"FPR={stats['fpr']:.4f}  TPR={stats['tpr']:.4f}  "
            f"(tp {stats['tp']} / fn {stats['fn']} / fp {stats['fp']} / tn {stats['tn']})"
        )
    print()
    print(f"threshold {args.threshold}: FPR {shipped['fpr']:.4f} (target <= {TARGET_FPR}), TPR {shipped['tpr']:.4f}")
    print(f"recommended threshold for FPR <= {TARGET_FPR}: {shipped['recommended']}")
    print()

    print("Highest-scoring cross-author pairs")
    print("-" * 78)
    for entry in shipped["worst_false_positives"]:
        flag = "FALSE POSITIVE" if entry["above_threshold"] else ""
        print(f"  {entry['author']:<8} pair {entry['pair']}  score={entry['score']:.4f}  {flag}")

    if args.sweep:
        print()
        print("Threshold sweep")
        print("-" * 78)
        for cut in sorted({r["score"] for r in scored["ensemble"] if r["score"] is not None}, reverse=True):
            stats = rates_at(scored["ensemble"], cut)
            print(f"  {cut:.4f}  FPR={stats['fpr']:.4f}  TPR={stats['tpr']:.4f}")

    if not args.no_report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(build_report(args.corpus, scored, shipped), encoding="utf-8")
        print(f"\nreport written: {args.report}")

    print("=" * 78)

    if args.check_threshold is not None:
        stats = rates_at(scored["ensemble"], args.check_threshold)
        if stats["fpr"] > TARGET_FPR:
            print(
                f"FAIL: FPR {stats['fpr']:.4f} at threshold {args.check_threshold} exceeds "
                f"the {TARGET_FPR} budget",
                file=sys.stderr,
            )
            return 1
        print(f"OK: FPR {stats['fpr']:.4f} <= {TARGET_FPR} at threshold {args.check_threshold}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
