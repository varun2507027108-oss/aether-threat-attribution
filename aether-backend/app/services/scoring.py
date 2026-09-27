"""Calibrated attribution confidence scoring for Project AETHER.

The engine replaces fixed percentage weighting with two mathematically
defensible mechanisms:

1. **Naive-Bayes log-odds fusion.** Every indicator is expressed as a
   likelihood ratio (LR) against the hypothesis *"this subject is the actor we
   attribute to"*. Combining evidence is a sum of log LRs plus the prior
   log-odds, mapped through a sigmoid to a probability in [0, 1]. This makes the
   score monotone: adding supporting evidence can never lower the result.

2. **Dempster-Shafer conflict analysis.** Each indicator also carries a belief
   mass over {H, not-H, Theta}. Masses are combined with Dempster's rule; the
   accumulated conflict mass K (evidence pointed in both directions) triggers a
   documented discount, because a case where the evidence disagrees with itself
   must never be presented to a court as a high-confidence attribution.

Both layers are computed over the same evidence list, and every number in the
response is explainable: each indicator reports its own LR, stance, and share of
the total log-odds contribution.

Calibration of the LR table is driven by ``scripts/calibrate.py`` against the
labelled corpus in ``docs/validation/historical_cases.json``.
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ============================================================================ #
# Configuration
# ============================================================================ #

STANCE_SUPPORTS = "supports"
STANCE_CONTRADICTS = "contradicts"
STANCE_NEUTRAL = "neutral"

CATEGORY_DETERMINISTIC = "deterministic"
CATEGORY_PROBABILISTIC = "probabilistic"
CATEGORY_BEHAVIORAL = "behavioral"

VALID_CATEGORIES = (CATEGORY_DETERMINISTIC, CATEGORY_PROBABILISTIC, CATEGORY_BEHAVIORAL)
VALID_STANCES = (STANCE_SUPPORTS,STANCE_CONTRADICTS, STANCE_NEUTRAL)

# Base-rate confidence assigned to each indicator before discounting for
# ignorance. 0.9 is deliberately not 1.0: a Bayesian base mass of m(Theta) = 0.1
# keeps the combination stable when evidence is thin, instead of letting one
# indicator dominate the frame.
DEFAULT_CONFIDENCE_WEIGHT = 0.9

DEFAULT_CONFLICT_THRESHOLD = 0.6
DEFAULT_MAX_CONFLICT_DISCOUNT = 0.75

# Conflict mass is treated as a continuum rather than a switch. Above this floor
# the posterior is progressively discounted; above the hard threshold (default
# 0.6) the case is additionally flagged as a conflict in the reporting tier.
# A hard switch alone was too brittle in practice: real cases with two strong
# supporting indicators and one strong refutation land around K = 0.55, where a
# binary threshold would silently apply no discount at all.
DEFAULT_ELEVATED_CONFLICT_FLOOR = 0.35


def get_prior_odds() -> float:
    """Resolve the prior probability that an investigated subject is the actor.

    Configured as ``AETHER_PRIOR_ODDS`` using a ``numerator:denominator`` form
    (default ``1:9``, i.e. a 10% base rate). Unparsable values fall back to the
    documented default rather than aborting a scoring run.
    """
    raw = os.getenv("AETHER_PRIOR_ODDS", "1:9").strip() or "1:9"
    numerator, _, denominator = raw.partition(":")
    try:
        num = float(numerator)
        den = float(denominator) if denominator else 1.0
    except ValueError:
        return 0.1
    if num <= 0 or den <= 0 or num + den <= 0:
        return 0.1
    return max(1e-6, min(1 - 1e-6, num / (num + den)))


def get_conflict_threshold() -> float:
    raw = os.getenv("AETHER_CONFLICT_THRESHOLD", "").strip()
    if not raw:
        return DEFAULT_CONFLICT_THRESHOLD
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError:
        return DEFAULT_CONFLICT_THRESHOLD


def get_elevated_conflict_floor() -> float:
    raw = os.getenv("AETHER_ELEVATED_CONFLICT_FLOOR", "").strip()
    if not raw:
        return DEFAULT_ELEVATED_CONFLICT_FLOOR
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError:
        return DEFAULT_ELEVATED_CONFLICT_FLOOR


def conflict_discount(
    conflict_mass: float,
    elevated_floor: float = DEFAULT_ELEVATED_CONFLICT_FLOOR,
    max_discount: float = DEFAULT_MAX_CONFLICT_DISCOUNT,
) -> float:
    """Graded discount factor for a given conflict mass.

    Returns 0.0 while the frame is internally consistent, then ramps linearly to
    ``max_discount`` as the conflict approaches total. Capping the discount keeps
    a self-contradicting frame at "inconclusive" rather than collapsing to a
    confident 0.0, which would be its own kind of false claim.
    """
    if conflict_mass <= elevated_floor:
        return 0.0
    span = max(1e-9, 1.0 - elevated_floor)
    ramp = min(1.0, (conflict_mass - elevated_floor) / span)
    return min(max_discount, ramp * max_discount)


# ============================================================================ #
# Likelihood ratio table
# ============================================================================ #

@dataclass(frozen=True)
class LRProfile:
    """Calibration parameters for a single attribution indicator.

    Attributes:
        category: Evidence class (deterministic / probabilistic / behavioral).
        lr_full: Likelihood ratio when the indicator matches at full strength.
        description: Human-readable statement of what the LR encodes.
        contradicted: LR applied when the indicator actively refutes attribution.
    """

    category: str
    lr_full: float
    description: str
    contradicted: float = 1.0 / 8.0

    def scaled(self, strength: float) -> float:
        """Interpolate the LR for a graded match.

        Uses ``exp(ln(lr_full) * strength)`` so that strength 0 yields LR 1.0
        (the indicator carries no information) and strength 1 yields ``lr_full``,
        with a strictly monotone path in between. Linear interpolation of the LR
        itself would overshoot near zero and break monotonicity.
        """
        clamped = max(0.0, min(1.0, float(strength)))
        return math.exp(math.log(max(self.lr_full, 1e-9)) * clamped)

    def scaled_contradiction(self, strength: float) -> float:
        """LR for an active refutation.

        Uses the same interpolation as :meth:`scaled` but anchored on
        ``contradicted``, which is below 1.0, so the result moves from 1.0 (no
        information) down to ``contradicted`` (a full refutation).
        """
        clamped = max(0.0, min(1.0, float(strength)))
        return math.exp(math.log(max(self.contradicted, 1e-9)) * clamped)


# The table is the single source of truth for how much each indicator moves the
# posterior. Values are set from the labelled corpus in
# docs/validation/historical_cases.json and refined by scripts/calibrate.py.
LIKELIHOOD_RATIO_TABLE: Dict[str, LRProfile] = {
    "pgp_match": LRProfile(
        CATEGORY_DETERMINISTIC, 20.0,
        "Reuse of a known PGP key across infrastructure attributed to the same subject.",
    ),
    "origin_ip_match": LRProfile(
        CATEGORY_DETERMINISTIC, 12.0,
        "Server-status / metadata leak exposing an origin IP tied to the subject.",
    ),
    "btc_cluster_match": LRProfile(
        CATEGORY_DETERMINISTIC, 8.0,
        "Bitcoin peel-chain clustering links extortion wallets to the subject.",
    ),
    "favicon_match": LRProfile(
        CATEGORY_DETERMINISTIC, 1.5,
        "Identical Shodan favicon MurmurHash3 across hosts. Kept weak on purpose: "
        "default and framework icons are shared by thousands of unrelated hosts, so a "
        "favicon match is a search lead, not an attribution artefact.",
    ),
    "tls_cert_match": LRProfile(
        CATEGORY_DETERMINISTIC, 25.0,
        "Reused TLS leaf certificate fingerprint across unrelated clearnet hosts.",
    ),
    "stylometry_similarity": LRProfile(
        CATEGORY_PROBABILISTIC, 3.0,
        "Author-profiling similarity of threat-note prose against a known corpus.",
    ),
    "diurnal_consistency": LRProfile(
        CATEGORY_BEHAVIORAL, 2.0,
        "Operational activity clustered around the subject's inferred sleep trough.",
    ),
    "ct_log_overlap": LRProfile(
        CATEGORY_PROBABILISTIC, 6.0,
        "Onion address or key material observed in Certificate Transparency logs.",
    ),
    "infrastructure_reuse": LRProfile(
        CATEGORY_DETERMINISTIC, 2.5,
        "Shared hosting ASN, scanner banner, or deployment artefact across incidents. "
        "Deliberately weak: Tor exits and bulletproof hosts are shared by many unrelated actors.",
    ),
}

# Signals that arrive without an entry in the table still score, using a
# conservative default so a new indicator degrades to "weak evidence" instead of
# failing the run.
DEFAULT_PROFILE = LRProfile(CATEGORY_PROBABILISTIC, 2.0, "Uncalibrated indicator.")


def get_profile(name: str) -> LRProfile:
    return LIKELIHOOD_RATIO_TABLE.get(name, DEFAULT_PROFILE)


# ============================================================================ #
# Evidence model
# ============================================================================ #

@dataclass(frozen=True)
class Evidence:
    """A single attribution indicator ready for probabilistic fusion."""

    name: str
    category: str
    raw_value: Any
    likelihood_ratio: float
    stance: str = STANCE_SUPPORTS
    detail: str = ""
    specificity: float = 1.0
    key_id: Optional[str] = field(default=None, compare=False)

    @property
    def log_odds(self) -> float:
        """Log-likelihood ratio contribution in nats."""
        return math.log(max(self.likelihood_ratio, 1e-12))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.name,
            "category": self.category,
            "raw_value": self.raw_value,
            "stance": self.stance,
            "likelihood_ratio": round(self.likelihood_ratio, 6),
            "log_likelihood_ratio": round(self.log_odds, 6),
            "detail": self.detail,
        }


def make_evidence(
    name: str,
    strength: float,
    *,
    stance: str = STANCE_SUPPORTS,
    raw_value: Any = None,
    detail: str = "",
) -> Evidence:
    """Build an :class:`Evidence` from a graded indicator strength in [0, 1].

    ``strength`` 0.0 yields LR 1.0, so absent or uninformative indicators
    contribute nothing to the posterior in either direction. The same value is
    carried as ``specificity``, which controls how much belief mass the
    Dempster-Shafer layer commits on this indicator.
    """
    if stance not in VALID_STANCES:
        raise ValueError(f"Unknown stance {stance!r}; expected one of {VALID_STANCES}")

    profile = get_profile(name)
    clamped = max(0.0, min(1.0, float(strength)))
    value = raw_value if raw_value is not None else clamped

    if stance == STANCE_SUPPORTS:
        lr = profile.scaled(clamped)
    elif stance == STANCE_CONTRADICTS:
        lr = profile.scaled_contradiction(clamped)
    else:
        lr = 1.0

    return Evidence(
        name=name,
        category=profile.category,
        raw_value=value,
        likelihood_ratio=lr,
        stance=stance,
        detail=detail or profile.description,
        specificity=clamped,
    )


def _evidence_from_signals(signals: Dict[str, float], default_stance: str = STANCE_SUPPORTS) -> List[Evidence]:
    return [make_evidence(name, value, stance=default_stance) for name, value in signals.items()]


# ============================================================================ #
# Numerical helpers
# ============================================================================ #

def sigmoid(x: float) -> float:
    """Numerically stable logistic function."""
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    exp_x = math.exp(x)
    return exp_x / (1.0 + exp_x)


def logit(p: float) -> float:
    """Inverse of :func:`sigmoid`, clamped away from the asymptotes."""
    clamped = max(1e-9, min(1 - 1e-9, float(p)))
    return math.log(clamped / (1 - clamped))


def belief_masses(
    likelihood_ratio: float,
    weight: float = DEFAULT_CONFIDENCE_WEIGHT,
    specificity: float = 1.0,
    stance: str = STANCE_SUPPORTS,
) -> Dict[str, float]:
    """Split an indicator into Dempster-Shafer base masses over {H, notH, Theta}.

    Each indicator is treated as an *unambiguous* specification: evidence that
    supports attribution is assigned no mass to not-H, and evidence that refutes
    attribution is assigned no mass to H. The ``weight * specificity`` fraction
    is the partial-completeness term; the remainder stays in Theta as ignorance.

    The unambiguous construction is what keeps pure agreement conflict-free.
    A symmetric split (m(H) and m(notH) both proportional to the LR) looks
    tidier on paper but makes every pair of agreeing indicators generate
    conflict out of their residual ignorance, so a five-indicator concordant
    case trips the conflict threshold while a genuinely self-contradicting case
    does not. That is precisely backwards.
    """
    confidence = max(0.0, min(1.0, float(weight)))
    specific = max(0.0, min(1.0, float(specificity)))
    lr = max(1e-9, float(likelihood_ratio))

    if stance == STANCE_CONTRADICTS or lr < 1.0:
        committed = confidence * specific
        return {"h": 0.0, "not_h": committed, "theta": 1.0 - committed}
    if stance == STANCE_NEUTRAL or abs(lr - 1.0) < 1e-12:
        return {"h": 0.0, "not_h": 0.0, "theta": 1.0}
    committed = confidence * specific
    return {"h": committed, "not_h": 0.0, "theta": 1.0 - committed}


def combine_masses(
    left: Dict[str, float],
    right: Dict[str, float],
) -> Tuple[Dict[str, float], float]:
    """Combine two mass assignments with Dempster's rule of combination.

    Returns the normalized masses and the conflict mass ``K`` that had to be
    discarded. Discarding K is exactly the assumption that the frame is
    non-empty, so K is also the confidence discount the caller should apply.
    """
    k = (
        left["h"] * right["not_h"]
        + left["not_h"] * right["h"]
    )
    if k >= 1.0 - 1e-12:
        # Total conflict: every hypothesis is ruled out. There is no normalized
        # combination, so hand back an all-ignorance assignment and let the
        # caller discount by the full conflict.
        return {"h": 0.0, "not_h": 0.0, "theta": 1.0}, 1.0

    denom = 1.0 - k
    return (
        {
            "h": (left["h"] * right["h"]) / denom,
            "not_h": (left["not_h"] * right["not_h"]) / denom,
            "theta": (left["theta"] * right["theta"]
                      + left["h"] * right["theta"]
                      + left["theta"] * right["h"]
                      + left["not_h"] * right["theta"]
                      + left["theta"] * right["not_h"]) / denom,
        },
        k,
    )


def conflicting_pairs(evidence: Sequence[Evidence]) -> List[Dict[str, Any]]:
    """List supporting/contradicting indicator pairs that pull against each other.

    The score is the product of the two indicators' opposing beliefs, which is
    the amount of mass that pair alone sends to conflict.
    """
    supports = [e for e in evidence if e.stance == STANCE_SUPPORTS]
    refutes = [e for e in evidence if e.stance == STANCE_CONTRADICTS]

    pairs: List[Dict[str, Any]] = []
    for support in supports:
        support_masses = belief_masses(
            support.likelihood_ratio, specificity=support.specificity, stance=support.stance
        )
        for refute in refutes:
            refute_masses = belief_masses(
                refute.likelihood_ratio, specificity=refute.specificity, stance=refute.stance
            )
            conflict = support_masses["h"] * refute_masses["not_h"] + support_masses["not_h"] * refute_masses["h"]
            pairs.append(
                {
                    "supporting_indicator": support.name,
                    "contradicting_indicator": refute.name,
                    "conflict_mass": round(conflict, 6),
                    "note": (
                        f"{support.name} supports attribution while {refute.name} "
                        "refutes it; this pair cannot both be true."
                    ),
                }
            )

    pairs.sort(key=lambda pair: pair["conflict_mass"], reverse=True)
    return pairs


# ============================================================================ #
# Core scoring engine
# ============================================================================ #

def score_evidence(
    evidence: Iterable[Evidence],
    *,
    prior: Optional[float] = None,
    conflict_threshold: Optional[float] = None,
    confidence_weight: float = DEFAULT_CONFIDENCE_WEIGHT,
) -> Dict[str, Any]:
    """Fuse attribution indicators into a calibrated posterior probability.

    The returned dictionary is intentionally verbose: every intermediate value a
    reviewer, opposing counsel, or judge might ask about is present.
    """
    items = list(evidence)
    prior_p = get_prior_odds() if prior is None else max(1e-6, min(1 - 1e-6, float(prior)))
    threshold = get_conflict_threshold() if conflict_threshold is None else float(conflict_threshold)
    elevated_floor = get_elevated_conflict_floor()
    prior_log_odds = logit(prior_p)

    log_lr_total = sum(item.log_odds for item in items)
    posterior_log_odds = prior_log_odds + log_lr_total
    posterior = sigmoid(posterior_log_odds)

    # Dempster-Shafer layer over the same evidence.
    #
    # The accumulator is seeded with the first indicator's own masses, NOT with
    # a vacuous {0, 0, 1} assignment: Theta is the *ignorance* set, and combining
    # with it multiplies every non-Theta mass by zero, so it annihilates the
    # frame instead of acting as a neutral identity. (The true Dempster identity
    # is the total set, which would inject spurious conflict on the first item.)
    combined = {"h": 0.0, "not_h": 0.0, "theta": 1.0}
    conflict_product = 1.0
    for index, item in enumerate(items):
        masses = belief_masses(
            item.likelihood_ratio,
            confidence_weight,
            specificity=item.specificity,
            stance=item.stance,
        )
        if index == 0:
            combined, k = masses, 0.0
        else:
            combined, k = combine_masses(combined, masses)
        conflict_product *= (1.0 - k)

    conflict_mass = round(1.0 - conflict_product, 6)
    conflict_detected = conflict_mass > threshold
    discount = conflict_discount(conflict_mass, elevated_floor)
    final_score = max(0.0, min(1.0, posterior * (1.0 - discount)))

    dempster_posterior = combined["h"] / (combined["h"] + combined["not_h"]) if (
        combined["h"] + combined["not_h"]
    ) > 0 else 0.0

    contributions = _build_contributions(items, prior_log_odds, final_score)
    refuters = [item.to_dict() for item in items if item.stance == STANCE_CONTRADICTS]
    supporters = [item for item in items if item.stance == STANCE_SUPPORTS]

    if conflict_detected:
        severity = "high"
    elif conflict_mass > elevated_floor:
        severity = "elevated"
    else:
        severity = "none"

    return {
        "confidence_score": round(final_score, 4),
        "confidence_tier": classify_confidence(final_score, conflict_detected=conflict_detected),
        "engine": "naive_bayes_log_odds+dempster_shafer",
        "posterior_probability": round(final_score, 6),
        "bayes_posterior": round(posterior, 6),
        "dempster_posterior": round(dempster_posterior, 6),
        "prior_probability": round(prior_p, 6),
        "prior_log_odds": round(prior_log_odds, 6),
        "log_likelihood_ratio_total": round(log_lr_total, 6),
        "posterior_log_odds": round(posterior_log_odds, 6),
        "conflict": {
            "conflict_mass": conflict_mass,
            "threshold": round(threshold, 6),
            "elevated_floor": round(elevated_floor, 6),
            "severity": severity,
            "conflict_detected": conflict_detected,
            "applied_discount": round(discount, 6),
            "dempster_masses": {k: round(v, 6) for k, v in combined.items()},
            "pairs": conflicting_pairs(items),
        },
        "contributions": contributions,
        "contradicting_evidence": refuters,
        "supporting_evidence_count": len(supporters),
        "indicator_count": len(items),
    }


def _build_contributions(
    items: Sequence[Evidence],
    prior_log_odds: float,
    final_score: float,
) -> List[Dict[str, Any]]:
    """Rank indicators by share of total log-odds movement.

    Shares are normalized over absolute log-odds so that a contradicting
    indicator reports a meaningful negative contribution instead of sorting to
    the bottom as "small".
    """
    magnitudes = {item.name: abs(item.log_odds) for item in items}
    total = sum(magnitudes.values())
    prior_share = abs(prior_log_odds)

    contributions: List[Dict[str, Any]] = []
    for item in items:
        share = (magnitudes[item.name] / total * 100.0) if total > 0 else 0.0
        contributions.append(
            {
                **item.to_dict(),
                "share_pct": round(share, 2),
                "direction": "up" if item.log_odds > 0 else ("down" if item.log_odds < 0 else "flat"),
            }
        )

    contributions.sort(key=lambda c: c["share_pct"], reverse=True)
    if prior_share > 0:
        contributions.append(
            {
                "indicator": "prior_base_rate",
                "category": "prior",
                "raw_value": None,
                "stance": STANCE_NEUTRAL,
                "likelihood_ratio": round(math.exp(-prior_log_odds), 6),
                "log_likelihood_ratio": round(-prior_log_odds, 6),
                "detail": "Base rate that an investigated subject is the attributed actor (AETHER_PRIOR_ODDS).",
                "share_pct": 0.0,
                "direction": "down" if final_score < 0.5 else "flat",
            }
        )
    return contributions


def classify_confidence(score: float, conflict_detected: bool = False) -> str:
    """Map a posterior to the reporting tier used in the dossier."""
    if conflict_detected:
        return "CONTRADICTION DETECTED - EVIDENCE CONFLICT"
    if score >= 0.90:
        return "DEFINITIVE JUDICIAL ATTRIBUTION"
    if score >= 0.75:
        return "HIGH FORENSIC CONFIDENCE"
    if score >= 0.50:
        return "MODERATE INVESTIGATIVE LEAD"
    return "INCONCLUSIVE / INSUFFICIENT EVIDENCE"


# ============================================================================ #
# Legacy entry point (retained for API and pipeline compatibility)
# ============================================================================ #

def calculate_calibrated_confidence(
    deterministic_signals: Dict[str, float],
    probabilistic_signals: Dict[str, float],
    contradictions: List[Dict[str, Any]] | None = None,
    weight_det: float = 0.70,
    weight_ai: float = 0.30,
) -> Dict[str, Any]:
    """Legacy signal-dict wrapper around :func:`score_evidence`.

    Kept for the ``POST /api/analysis/score`` contract and for callers that
    predate the Evidence model. Behaviour changes from fixed percentage
    weighting to LR fusion, so ``breakdown.s_det`` / ``s_ai`` are now reported
    as *category aggregates* (geometric-mean LR per category) rather than as
    weighted linear sub-scores.

    ``weight_det`` / ``weight_ai`` are accepted for backward compatibility and
    recorded in the response, but the Bayes fusion is unweighted: the LR table
    already encodes how much each indicator is worth, and re-weighting on top of
    that double-counts. Explicit ``contradictions`` are still applied as an
    additive penalty.
    """
    items: List[Evidence] = []
    items.extend(_evidence_from_signals(deterministic_signals or {}, STANCE_SUPPORTS))
    items.extend(_evidence_from_signals(probabilistic_signals or {}, STANCE_SUPPORTS))

    result = score_evidence(items)

    penalties_list = list(contradictions or [])
    total_penalty = round(sum(float(p.get("penalty", 0.0)) for p in penalties_list), 4)

    adjusted = result["confidence_score"]
    if total_penalty:
        adjusted = max(0.0, min(1.0, adjusted - total_penalty))

    conflict_detected = bool(result["conflict"]["conflict_detected"]) or total_penalty >= 0.35
    final_score = round(adjusted, 4)

    return {
        "confidence_score": final_score,
        "confidence_tier": classify_confidence(final_score, conflict_detected=conflict_detected),
        "engine": result["engine"],
        "posterior_probability": final_score,
        "conflict": {**result["conflict"], "legacy_penalty_applied": total_penalty},
        "contributions": result["contributions"],
        "contradicting_evidence": result["contradicting_evidence"],
        "breakdown": {
            "s_det": _category_score(items, CATEGORY_DETERMINISTIC),
            "s_ai": _category_score(items, CATEGORY_PROBABILISTIC),
            "weight_det": weight_det,
            "weight_ai": weight_ai,
            "total_penalty": total_penalty,
            "deterministic_inputs": _clamp_inputs(deterministic_signals),
            "probabilistic_inputs": _clamp_inputs(probabilistic_signals),
            "contradiction_penalties": penalties_list,
        },
    }


def _clamp_inputs(signals: Dict[str, float]) -> Dict[str, float]:
    return {name: round(max(0.0, min(1.0, float(value))), 4) for name, value in (signals or {}).items()}


def _category_score(items: Sequence[Evidence], category: str) -> float:
    """Geometric-mean LR expressed as a [0, 1] category strength.

    The geometric mean is used rather than the arithmetic mean because a single
    strongly contradicting indicator should drag the category down, which is the
    behaviour a reviewer expects from an evidence category.
    """
    category_items = [item for item in items if item.category == category]
    if not category_items:
        return 0.0
    mean_log_odds = sum(item.log_odds for item in category_items) / len(category_items)
    return round(sigmoid(mean_log_odds), 4)
