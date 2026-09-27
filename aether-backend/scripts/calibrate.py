"""Calibration harness for the AETHER likelihood-ratio table.

Runs the scoring engine over the labelled corpus in
``docs/validation/historical_cases.json`` and reports:

  * Brier score and log loss over the whole corpus
  * AUC computed with the Mann-Whitney U formulation
  * False positive rate at the configured decision threshold
  * A reliability diagram written to ``docs/calibration/reliability.png``
  * A suggested LR table: per-indicator scan over candidate multipliers, scored
    by Brier, with the improvement printed alongside

Usage:
    python scripts/calibrate.py                     # report + write diagram
    python scripts/calibrate.py --cases path.json   # alternate corpus
    python scripts/calibrate.py --no-plot           # skip PNG rendering
    python scripts/calibrate.py --csv out.csv       # per-case predictions
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.scoring import (  # noqa: E402
    DEFAULT_CONFLICT_THRESHOLD,
    LIKELIHOOD_RATIO_TABLE,
    LRProfile,
    get_conflict_threshold,
    get_prior_odds,
    make_evidence,
    score_evidence,
    STANCE_SUPPORTS,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
DEFAULT_CASES = REPO_ROOT / "docs" / "validation" / "historical_cases.json"
DEFAULT_RELIABILITY_PNG = REPO_ROOT / "docs" / "calibration" / "reliability.png"

# Decision threshold above which a case is reported as an attribution.
REPORTING_THRESHOLD = 0.5

# Per-indicator multipliers scanned when suggesting LR values.
CANDIDATE_MULTIPLIERS = (0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0)


# ============================================================================ #
# Corpus handling
# ============================================================================ #

def load_cases(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases", [])
    if not cases:
        raise SystemExit(f"No cases found in {path}")
    return cases


def case_to_evidence(case: Dict[str, Any]) -> List[Any]:
    stances = case.get("stances", {})
    raw_values = case.get("raw_values", {})
    return [
        make_evidence(
            name,
            strength,
            stance=stances.get(name, STANCE_SUPPORTS),
            raw_value=raw_values.get(name, strength),
            detail=case.get("rationale", ""),
        )
        for name, strength in (case.get("signals") or {}).items()
    ]


def predict(case: Dict[str, Any], prior: float, threshold: float) -> Dict[str, Any]:
    result = score_evidence(
        case_to_evidence(case),
        prior=prior,
        conflict_threshold=threshold,
    )
    return {
        "case_id": case.get("id"),
        "vector": case.get("vector"),
        "label": int(case["label"]),
        "probability": result["confidence_score"],
        "predicted": 1 if result["confidence_score"] >= REPORTING_THRESHOLD else 0,
        "conflict_detected": result["conflict"]["conflict_detected"],
        "confidence_tier": result["confidence_tier"],
    }


# ============================================================================ #
# Metrics
# ============================================================================ #

def brier_score(rows: Sequence[Dict[str, Any]]) -> float:
    """Mean squared error of the probability estimates (lower is better)."""
    if not rows:
        return float("nan")
    return sum((row["probability"] - row["label"]) ** 2 for row in rows) / len(rows)


def log_loss(rows: Sequence[Dict[str, Any]]) -> float:
    """Mean negative log likelihood, clamped to avoid infinities."""
    if not rows:
        return float("nan")
    total = 0.0
    for row in rows:
        p = max(1e-9, min(1 - 1e-9, row["probability"]))
        total += -(row["label"] * math.log(p) + (1 - row["label"]) * math.log(1 - p))
    return total / len(rows)


def auc(rows: Sequence[Dict[str, Any]]) -> float:
    """Mann-Whitney U AUC with tie handling. 0.5 is chance-level separation."""
    positives = [row["probability"] for row in rows if row["label"] == 1]
    negatives = [row["probability"] for row in rows if row["label"] == 0]
    if not positives or not negatives:
        return float("nan")

    wins = 0.0
    for pos in positives:
        for neg in negatives:
            if pos > neg:
                wins += 1.0
            elif pos == neg:
                wins += 0.5
    return wins / (len(positives) * len(negatives))


def false_positive_rate(rows: Sequence[Dict[str, Any]]) -> float:
    """Fraction of non-attributed cases scored above the reporting threshold."""
    negatives = [row for row in rows if row["label"] == 0]
    if not negatives:
        return 0.0
    return sum(1 for row in negatives if row["predicted"] == 1) / len(negatives)


def confusion(rows: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "tp": sum(1 for r in rows if r["label"] == 1 and r["predicted"] == 1),
        "fp": sum(1 for r in rows if r["label"] == 0 and r["predicted"] == 1),
        "tn": sum(1 for r in rows if r["label"] == 0 and r["predicted"] == 0),
        "fn": sum(1 for r in rows if r["label"] == 1 and r["predicted"] == 0),
    }


def reliability_bins(rows: Sequence[Dict[str, Any]], n_bins: int = 10) -> List[Dict[str, float]]:
    """Bucket predictions into equal-width probability bins.

    A well-calibrated engine puts the empirical attribution rate in each bin on
    the diagonal. ``count`` is retained so a reader can see which buckets are
    supported by enough data to mean anything.
    """
    bins: List[Dict[str, float]] = []
    for index in range(n_bins):
        low = index / n_bins
        high = (index + 1) / n_bins
        members = [r for r in rows if (r["probability"] >= low and (r["probability"] < high or (index == n_bins - 1 and r["probability"] <= high)))]
        bins.append(
            {
                "low": low,
                "high": high,
                "predicted": (low + high) / 2,
                "observed": (sum(r["label"] for r in members) / len(members)) if members else float("nan"),
                "count": len(members),
            }
        )
    return bins


# ============================================================================ #
# LR suggestion
# ============================================================================ #

def suggest_likelihood_ratios(
    cases: Sequence[Dict[str, Any]],
    prior: float,
    threshold: float,
) -> List[Dict[str, Any]]:
    """Coordinate-descent scan: for each indicator, find the LR multiplier that
    minimises Brier score with every other indicator held at its current value.

    This is a greedy coordinate search, not a global optimum. It is run offline
    against a human-labelled corpus, so the output is a *suggestion* an analyst
    must review rather than a value to auto-apply.
    """
    from app.services import scoring as scoring_module

    original = dict(scoring_module.LIKELIHOOD_RATIO_TABLE)
    baseline = brier_score([
        predict(case, prior, threshold) for case in cases
    ])

    suggestions: List[Dict[str, Any]] = []
    try:
        for name, profile in original.items():
            best_multiplier = 1.0
            best_brier = baseline
            for multiplier in CANDIDATE_MULTIPLIERS:
                if multiplier == 1.0:
                    continue
                trial = LRProfile(
                    profile.category,
                    profile.lr_full * multiplier,
                    profile.description,
                    profile.contradicted / multiplier,
                )
                scoring_module.LIKELIHOOD_RATIO_TABLE[name] = trial
                score = brier_score([predict(case, prior, threshold) for case in cases])
                if score < best_brier - 1e-9:
                    best_brier = score
                    best_multiplier = multiplier

            scoring_module.LIKELIHOOD_RATIO_TABLE[name] = trial if best_multiplier != 1.0 else profile
            if best_multiplier != 1.0:
                suggestions.append(
                    {
                        "indicator": name,
                        "current_lr": profile.lr_full,
                        "suggested_multiplier": best_multiplier,
                        "suggested_lr": round(profile.lr_full * best_multiplier, 4),
                        "brier_before": round(baseline, 6),
                        "brier_after": round(best_brier, 6),
                        "note": "Improves Brier score on the labelled corpus; verify against a held-out set before adopting.",
                    }
                )
            baseline = min(baseline, best_brier)
    finally:
        scoring_module.LIKELIHOOD_RATIO_TABLE.clear()
        scoring_module.LIKELIHOOD_RATIO_TABLE.update(original)

    suggestions.sort(key=lambda item: item["brier_after"] - item["brier_before"])
    return suggestions


# ============================================================================ #
# Reliability diagram
# ============================================================================ #

def write_reliability_diagram(bins: Sequence[Dict[str, float]], path: Path) -> bool:
    """Render the reliability diagram, returning False when matplotlib is absent."""
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False

    path.parent.mkdir(parents=True, exist_ok=True)

    fig, (ax, ax_hist) = plt.subplots(
        2, 1, figsize=(6.4, 7.2), sharex=True,
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.08},
    )

    ax.plot([0, 1], [0, 1], linestyle="--", linewidth=1, color="#64748b", label="perfect calibration")
    observed = [(b["predicted"], b["observed"]) for b in bins if b["count"] > 0 and not math.isnan(b["observed"])]
    if observed:
        ax.plot(
            [p for p, _ in observed], [o for _, o in observed],
            marker="o", linewidth=2, color="#22d3ee", label="AETHER engine",
        )
        for predicted, obs in observed:
            ax.annotate(
                f"n={next(b['count'] for b in bins if b['predicted'] == predicted)}",
                (predicted, obs), textcoords="offset points", xytext=(6, -10),
                fontsize=7, color="#94a3b8",
            )

    ax.set_ylabel("Empirical attribution rate")
    ax.set_title("AETHER attribution reliability diagram", color="#e2e8f0")
    ax.legend(loc="upper left", fontsize=8)
    ax.grid(alpha=0.2)

    heights = [b["count"] for b in bins]
    ax_hist.bar([b["predicted"] for b in bins], heights, width=0.08, color="#1e293b", edgecolor="#22d3ee")
    ax_hist.set_xlabel("Predicted probability")
    ax_hist.set_ylabel("Cases")
    ax_hist.grid(alpha=0.2)

    for axis in (ax, ax_hist):
        axis.set_facecolor("#0f172a")
        axis.tick_params(colors="#94a3b8")
        for spine in axis.spines.values():
            spine.set_color("#1e293b")
    ax.xaxis.label.set_color("#e2e8f0")
    ax.yaxis.label.set_color("#e2e8f0")
    ax_hist.xaxis.label.set_color("#e2e8f0")
    ax_hist.yaxis.label.set_color("#e2e8f0")
    ax.title.set_color("#e2e8f0")

    fig.patch.set_facecolor("#0f172a")
    fig.savefig(path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return True


# ============================================================================ #
# Entry point
# ============================================================================ #

def write_predictions(rows: Sequence[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["case_id", "vector", "label", "probability", "predicted", "conflict_detected", "confidence_tier"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate the AETHER likelihood-ratio table.")
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES, help="labelled corpus JSON")
    parser.add_argument("--reliability-png", type=Path, default=DEFAULT_RELIABILITY_PNG)
    parser.add_argument("--csv", type=Path, default=None, help="write per-case predictions to CSV")
    parser.add_argument("--no-plot", action="store_true", help="skip reliability diagram rendering")
    parser.add_argument("--no-suggest", action="store_true", help="skip the LR multiplier scan")
    args = parser.parse_args(argv)

    if not args.cases.exists():
        print(f"error: corpus not found: {args.cases}", file=sys.stderr)
        return 2

    cases = load_cases(args.cases)
    prior = get_prior_odds()
    threshold = get_conflict_threshold()

    print("=" * 78)
    print("AETHER likelihood-ratio calibration report")
    print("=" * 78)
    print(f"corpus            : {args.cases}")
    print(f"cases             : {len(cases)}")
    print(f"prior odds        : {prior:.4f} (AETHER_PRIOR_ODDS={prior:.4f} -> probability)")
    print(f"conflict threshold: {threshold}")
    print(f"reporting cutoff  : {REPORTING_THRESHOLD}")
    print()

    rows = [predict(case, prior, threshold) for case in cases]
    bins = reliability_bins(rows)

    print("Per-case predictions")
    print("-" * 78)
    print(f"{'case':<38} {'label':>5} {'p':>7}  {'pred':>4}  conflict  tier")
    for row in rows:
        flag = "YES" if row["conflict_detected"] else "-"
        print(f"{row['case_id']:<38} {row['label']:>5} {row['probability']:>7.4f}  {row['predicted']:>4}  {flag:>8}  {row['confidence_tier']}")

    matrix = confusion(rows)
    print()
    print("Metrics")
    print("-" * 78)
    print(f"Brier score          : {brier_score(rows):.4f}")
    print(f"Log loss             : {log_loss(rows):.4f}")
    print(f"AUC                  : {auc(rows):.4f}")
    print(f"False positive rate  : {false_positive_rate(rows):.4f}")
    print(f"Confusion TP/FP/TN/FN: {matrix['tp']}/{matrix['fp']}/{matrix['tn']}/{matrix['fn']}")
    print()

    print("Reliability")
    print("-" * 78)
    for entry in bins:
        if not entry["count"]:
            continue
        print(f"[{entry['low']:.1f}, {entry['high']:.1f})  n={entry['count']:<3} observed={entry['observed']:.4f}")

    if args.no_plot:
        print("\nreliability diagram: skipped (--no-plot)")
    elif write_reliability_diagram(bins, args.reliability_png):
        print(f"\nreliability diagram: {args.reliability_png}")
    else:
        print("\nreliability diagram: matplotlib unavailable, install it with "
              "`pip install -r requirements-dev.txt` to render the PNG")

    if args.csv:
        write_predictions(rows, args.csv)
        print(f"per-case predictions: {args.csv}")

    if not args.no_suggest:
        print()
        print("Suggested LR adjustments (greedy coordinate scan, min Brier)")
        print("-" * 78)
        suggestions = suggest_likelihood_ratios(cases, prior, threshold)
        if not suggestions:
            print("No single-indicator multiplier improved the Brier score.")
        for item in suggestions:
            print(
                f"{item['indicator']:<24} {item['current_lr']:>6.2f} -> {item['suggested_lr']:>7.2f}  "
                f"Brier {item['brier_before']:.4f} -> {item['brier_after']:.4f}"
            )
        print("\nCurrent table:")
        for name, profile in LIKELIHOOD_RATIO_TABLE.items():
            print(f"  {name:<26} {profile.category:<14} lr_full={profile.lr_full}")

    print()
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
