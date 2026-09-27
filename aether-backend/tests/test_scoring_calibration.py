"""Phase 6 — calibrated scoring: LR fusion, Dempster-Shafer conflict, explainability."""

import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.scoring import (
    CATEGORY_BEHAVIORAL,
    CATEGORY_DETERMINISTIC,
    CATEGORY_PROBABILISTIC,
    DEFAULT_CONFLICT_THRESHOLD,
    LIKELIHOOD_RATIO_TABLE,
    STANCE_CONTRADICTS,
    STANCE_NEUTRAL,
    STANCE_SUPPORTS,
    belief_masses,
    classify_confidence,
    combine_masses,
    conflicting_pairs,
    conflict_discount,
    get_prior_odds,
    logit,
    make_evidence,
    score_evidence,
    sigmoid,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
CORPUS_PATH = REPO_ROOT / "docs" / "validation" / "historical_cases.json"


@pytest.fixture(autouse=True)
def _neutral_scoring_env(monkeypatch):
    for var in (
        "AETHER_PRIOR_ODDS",
        "AETHER_CONFLICT_THRESHOLD",
        "AETHER_ELEVATED_CONFLICT_FLOOR",
    ):
        monkeypatch.delenv(var, raising=False)


# --------------------------------------------------------------------------- #
# Numerical helpers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [-40.0, -6.0, -1.0, 0.0, 0.5, 3.0, 25.0, 400.0])
def test_sigmoid_is_stable_at_extremes(value):
    result = sigmoid(value)
    assert 0.0 <= result <= 1.0
    assert not math.isinf(result) and not math.isnan(result)
    # A naive exp(x) would overflow well before +400.
    if value > 100:
        assert result == pytest.approx(1.0)


def test_sigmoid_and_logit_round_trip():
    for p in (0.01, 0.25, 0.5, 0.73, 0.99):
        assert sigmoid(logit(p)) == pytest.approx(p, rel=1e-9)


def test_logit_clamps_away_from_asymptotes():
    assert math.isfinite(logit(0.0))
    assert math.isfinite(logit(1.0))
    assert logit(0.0) < logit(0.5) < logit(1.0)


# --------------------------------------------------------------------------- #
# Prior odds
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw,expected",
    [("1:9", 0.1), ("1:1", 0.5), ("3:7", 0.3), ("1:99", 0.01), ("5", 0.8333333)],
)
def test_prior_odds_parsing(monkeypatch, raw, expected):
    monkeypatch.setenv("AETHER_PRIOR_ODDS", raw)
    assert get_prior_odds() == pytest.approx(expected, rel=1e-5)


@pytest.mark.parametrize("raw", ["", "garbage", "0:5", "-1:2", "::", "0:0"])
def test_prior_odds_falls_back_to_default(monkeypatch, raw):
    monkeypatch.setenv("AETHER_PRIOR_ODDS", raw)
    assert get_prior_odds() == pytest.approx(0.1, rel=1e-6)


# --------------------------------------------------------------------------- #
# Evidence construction
# --------------------------------------------------------------------------- #

def test_zero_strength_indicator_is_neutral():
    evidence = make_evidence("pgp_match", 0.0)
    assert evidence.likelihood_ratio == pytest.approx(1.0)
    assert evidence.log_odds == pytest.approx(0.0)
    assert evidence.specificity == 0.0


def test_full_strength_indicator_hits_the_table_likelihood_ratio():
    for name, profile in LIKELIHOOD_RATIO_TABLE.items():
        assert make_evidence(name, 1.0).likelihood_ratio == pytest.approx(profile.lr_full, rel=1e-9)


def test_graded_interpolation_is_monotone_and_geometric():
    strengths = [i / 20 for i in range(21)]
    lrs = [make_evidence("stylometry_similarity", s).likelihood_ratio for s in strengths]
    assert all(lrs[i] < lrs[i + 1] for i in range(len(lrs) - 1))
    # Midpoint of a geometric interpolation is the geometric mean, not the
    # arithmetic mean: 3**0.5 = 1.732, not 2.0.
    assert lrs[10] == pytest.approx(math.sqrt(3.0), rel=1e-9)


def test_strength_is_clamped_to_the_unit_interval():
    assert make_evidence("pgp_match", 5.0).likelihood_ratio == pytest.approx(
        LIKELIHOOD_RATIO_TABLE["pgp_match"].lr_full
    )
    assert make_evidence("pgp_match", -3.0).likelihood_ratio == pytest.approx(1.0)


def test_contradicting_evidence_produces_a_likelihood_ratio_below_one():
    evidence = make_evidence("stylometry_similarity", 0.9, stance=STANCE_CONTRADICTS)
    assert evidence.likelihood_ratio < 1.0
    assert evidence.log_odds < 0.0


def test_neutral_stance_is_exactly_one():
    evidence = make_evidence("pgp_match", 1.0, stance=STANCE_NEUTRAL)
    assert evidence.likelihood_ratio == pytest.approx(1.0)


def test_unknown_stance_is_rejected():
    with pytest.raises(ValueError, match="Unknown stance"):
        make_evidence("pgp_match", 0.5, stance="maybe")


def test_unknown_indicator_degrades_to_a_weak_default():
    evidence = make_evidence("brand_new_indicator", 1.0)
    assert evidence.category == CATEGORY_PROBABILISTIC
    assert evidence.likelihood_ratio == pytest.approx(2.0)


def test_categories_are_populated_from_the_table():
    assert make_evidence("pgp_match", 0.5).category == CATEGORY_DETERMINISTIC
    assert make_evidence("stylometry_similarity", 0.5).category == CATEGORY_PROBABILISTIC
    assert make_evidence("diurnal_consistency", 0.5).category == CATEGORY_BEHAVIORAL


# --------------------------------------------------------------------------- #
# Belief masses
# --------------------------------------------------------------------------- #

def test_supporting_mass_is_unambiguous():
    masses = belief_masses(20.0, specificity=0.9, stance=STANCE_SUPPORTS)
    assert masses["not_h"] == 0.0
    assert masses["h"] == pytest.approx(0.81)
    assert masses["theta"] == pytest.approx(0.19)
    assert sum(masses.values()) == pytest.approx(1.0)


def test_refuting_mass_is_unambiguous():
    masses = belief_masses(0.15, specificity=0.8, stance=STANCE_CONTRADICTS)
    assert masses["h"] == 0.0
    assert masses["not_h"] == pytest.approx(0.72)
    assert sum(masses.values()) == pytest.approx(1.0)


def test_neutral_mass_is_pure_ignorance():
    masses = belief_masses(1.0, specificity=1.0, stance=STANCE_NEUTRAL)
    assert masses == {"h": 0.0, "not_h": 0.0, "theta": 1.0}


def test_agreeing_indicators_produce_zero_conflict():
    combined = {"h": 0.0, "not_h": 0.0, "theta": 1.0}
    masses = None
    for _ in range(6):
        item = belief_masses(20.0, specificity=0.9, stance=STANCE_SUPPORTS)
        masses, k = (item, 0.0) if masses is None else combine_masses(masses, item)
        assert k == pytest.approx(0.0)
    assert masses["theta"] < 1.0  # mass accumulated, not annihilated


def test_opposing_indicators_produce_conflict():
    support = belief_masses(20.0, specificity=1.0, stance=STANCE_SUPPORTS)
    refute = belief_masses(0.1, specificity=1.0, stance=STANCE_CONTRADICTS)
    _, k = combine_masses(support, refute)
    assert k == pytest.approx(0.81)


def test_combine_masses_normalizes_and_conserves_mass():
    left = belief_masses(20.0, specificity=0.9, stance=STANCE_SUPPORTS)
    right = belief_masses(5.0, specificity=0.7, stance=STANCE_SUPPORTS)
    combined, k = combine_masses(left, right)
    assert sum(combined.values()) == pytest.approx(1.0)
    assert k == pytest.approx(0.0)


def test_total_conflict_falls_back_to_ignorance_rather_than_dividing_by_zero():
    _, k = combine_masses(
        {"h": 1.0, "not_h": 0.0, "theta": 0.0},
        {"h": 0.0, "not_h": 1.0, "theta": 0.0},
    )
    assert k == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# Conflict discount
# --------------------------------------------------------------------------- #

def test_no_discount_below_the_elevated_floor():
    assert conflict_discount(0.0) == 0.0
    assert conflict_discount(0.34) == 0.0


def test_discount_ramps_between_floor_and_total():
    low = conflict_discount(0.36)
    mid = conflict_discount(0.675)
    high = conflict_discount(1.0)
    assert 0.0 < low < mid < high <= 0.75
    assert high == pytest.approx(0.75)


# --------------------------------------------------------------------------- #
# Core engine behaviour
# --------------------------------------------------------------------------- #

def test_empty_evidence_returns_the_prior():
    result = score_evidence([])
    assert result["confidence_score"] == pytest.approx(0.1, abs=1e-4)
    assert result["indicator_count"] == 0
    assert result["conflict"]["conflict_mass"] == 0.0
    assert result["confidence_tier"] == "INCONCLUSIVE / INSUFFICIENT EVIDENCE"


def test_single_strong_indicator_beats_the_prior():
    result = score_evidence([make_evidence("pgp_match", 1.0)])
    assert result["confidence_score"] > 0.1
    assert result["posterior_probability"] == pytest.approx(result["confidence_score"], abs=1e-4)


@pytest.mark.parametrize(
    "indicator,strength",
    [
        ("pgp_match", 0.2),
        ("origin_ip_match", 0.4),
        ("btc_cluster_match", 0.6),
        ("favicon_match", 0.8),
        ("tls_cert_match", 1.0),
        ("stylometry_similarity", 0.35),
        ("diurnal_consistency", 0.5),
        ("infrastructure_reuse", 0.65),
    ],
)
def test_monotonicity_adding_support_never_lowers_the_score(indicator, strength):
    base = score_evidence([make_evidence("pgp_match", 0.4)])
    extended = score_evidence([make_evidence("pgp_match", 0.4), make_evidence(indicator, strength)])
    assert extended["confidence_score"] >= base["confidence_score"] - 1e-9


def test_monotonicity_holds_across_many_indicator_orders():
    indicators = [
        make_evidence(name, strength)
        for name, strength in (
            ("pgp_match", 0.9), ("origin_ip_match", 0.7), ("btc_cluster_match", 0.5),
            ("stylometry_similarity", 0.4), ("diurnal_consistency", 0.3),
        )
    ]
    scores = [score_evidence(indicators[:n])["confidence_score"] for n in range(len(indicators) + 1)]
    assert scores == sorted(scores)


def test_scores_stay_within_the_unit_interval():
    loud = [make_evidence(name, 1.0) for name in LIKELIHOOD_RATIO_TABLE]
    assert 0.0 <= score_evidence(loud)["confidence_score"] <= 1.0

    opposed = [make_evidence(name, 1.0, stance=STANCE_CONTRADICTS) for name in LIKELIHOOD_RATIO_TABLE]
    assert 0.0 <= score_evidence(opposed)["confidence_score"] <= 1.0


def test_prior_shift_changes_the_posterior_without_changing_the_likelihoods():
    evidence = [make_evidence("origin_ip_match", 0.8)]
    sceptical = score_evidence(evidence, prior=0.001)
    generous = score_evidence(evidence, prior=0.5)
    assert sceptical["confidence_score"] < generous["confidence_score"]
    assert sceptical["log_likelihood_ratio_total"] == generous["log_likelihood_ratio_total"]


def test_conflict_is_detected_and_discounted_at_the_threshold():
    support = make_evidence("pgp_match", 1.0)
    refute = make_evidence("tls_cert_match", 1.0, stance=STANCE_CONTRADICTS)
    result = score_evidence([support, refute])

    assert result["conflict"]["conflict_detected"] is True
    assert result["conflict"]["conflict_mass"] > DEFAULT_CONFLICT_THRESHOLD
    assert result["conflict"]["severity"] == "high"
    assert result["conflict"]["applied_discount"] > 0.0
    assert result["confidence_score"] < result["bayes_posterior"]
    assert result["confidence_tier"] == "CONTRADICTION DETECTED - EVIDENCE CONFLICT"


def test_a_weak_refutation_does_not_trip_the_hard_threshold():
    result = score_evidence([
        make_evidence("pgp_match", 1.0),
        make_evidence("stylometry_similarity", 0.15, stance=STANCE_CONTRADICTS),
    ])
    assert result["conflict"]["conflict_detected"] is False
    assert result["confidence_tier"] != "CONTRADICTION DETECTED - EVIDENCE CONFLICT"


def test_conflict_threshold_is_configurable():
    support = make_evidence("pgp_match", 1.0)
    refute = make_evidence("tls_cert_match", 1.0, stance=STANCE_CONTRADICTS)
    assert score_evidence([support, refute], conflict_threshold=0.95)["conflict"]["conflict_detected"] is False
    assert score_evidence([support, refute], conflict_threshold=0.10)["conflict"]["conflict_detected"] is True


def test_conflicting_pairs_name_both_sides():
    support = make_evidence("origin_ip_match", 0.9)
    refute = make_evidence("diurnal_consistency", 0.8, stance=STANCE_CONTRADICTS)
    pairs = conflicting_pairs([support, refute])
    assert len(pairs) == 1
    assert pairs[0]["supporting_indicator"] == "origin_ip_match"
    assert pairs[0]["contradicting_indicator"] == "diurnal_consistency"
    assert pairs[0]["conflict_mass"] > 0.0


def test_agreeing_evidence_lists_no_conflicting_pairs():
    assert conflicting_pairs([make_evidence("pgp_match", 1.0), make_evidence("btc_cluster_match", 0.9)]) == []


# --------------------------------------------------------------------------- #
# Explainability
# --------------------------------------------------------------------------- #

def test_contributions_are_sorted_and_sum_to_roughly_100():
    result = score_evidence([
        make_evidence("pgp_match", 1.0),
        make_evidence("origin_ip_match", 0.6),
        make_evidence("stylometry_similarity", 0.3),
    ])
    shares = [c["share_pct"] for c in result["contributions"] if c["indicator"] != "prior_base_rate"]
    assert shares == sorted(shares, reverse=True)
    assert sum(shares) == pytest.approx(100.0, abs=0.5)


def test_contributions_report_direction_and_likelihood_ratio():
    result = score_evidence([
        make_evidence("pgp_match", 1.0),
        make_evidence("stylometry_similarity", 0.8, stance=STANCE_CONTRADICTS),
    ])
    by_name = {c["indicator"]: c for c in result["contributions"]}
    assert by_name["pgp_match"]["direction"] == "up"
    assert by_name["stylometry_similarity"]["direction"] == "down"
    assert by_name["pgp_match"]["likelihood_ratio"] > 1.0
    assert by_name["stylometry_similarity"]["likelihood_ratio"] < 1.0
    assert "prior_base_rate" in by_name


def test_contradicting_evidence_is_surfaced():
    refute = make_evidence("stylometry_similarity", 0.9, stance=STANCE_CONTRADICTS)
    result = score_evidence([make_evidence("pgp_match", 0.9), refute])
    assert len(result["contradicting_evidence"]) == 1
    assert result["contradicting_evidence"][0]["indicator"] == "stylometry_similarity"
    assert result["contradicting_evidence"][0]["stance"] == STANCE_CONTRADICTS


def test_engine_reports_its_provenance():
    result = score_evidence([make_evidence("pgp_match", 0.5)])
    assert result["engine"] == "naive_bayes_log_odds+dempster_shafer"
    assert result["supporting_evidence_count"] == 1
    assert result["indicator_count"] == 1
    assert "dempster_masses" in result["conflict"]


@pytest.mark.parametrize(
    "score,tier",
    [
        (0.95, "DEFINITIVE JUDICIAL ATTRIBUTION"),
        (0.80, "HIGH FORENSIC CONFIDENCE"),
        (0.60, "MODERATE INVESTIGATIVE LEAD"),
        (0.20, "INCONCLUSIVE / INSUFFICIENT EVIDENCE"),
    ],
)
def test_confidence_tiers(score, tier):
    assert classify_confidence(score) == tier


def test_conflict_overrides_the_tier():
    assert classify_confidence(0.99, conflict_detected=True) == "CONTRADICTION DETECTED - EVIDENCE CONFLICT"


# --------------------------------------------------------------------------- #
# Labelled corpus + calibration script
# --------------------------------------------------------------------------- #

def test_labelled_corpus_is_well_formed():
    payload = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    cases = payload["cases"]
    assert len(cases) >= 8
    labels = {case["label"] for case in cases}
    assert labels == {0, 1}
    for case in cases:
        assert case["id"] and case["vector"] and case["rationale"]
        for name, strength in (case.get("signals") or {}).items():
            assert 0.0 <= strength <= 1.0, f"{case['id']}: {name} out of range"
        for name, stance in (case.get("stances") or {}).items():
            assert name in (case.get("signals") or {}), f"{case['id']}: stance without a signal"
            assert stance in {STANCE_SUPPORTS, STANCE_CONTRADICTS, STANCE_NEUTRAL}


@pytest.mark.parametrize(
    "module_name",
    ["brier_score", "log_loss", "auc", "false_positive_rate", "reliability_bins", "predict"],
)
def test_calibration_helpers_are_importable(module_name):
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    import calibrate

    assert hasattr(calibrate, module_name)


def test_auc_extremes_and_brier_bounds():
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    from calibrate import auc, brier_score, false_positive_rate, load_cases, predict

    perfect = [
        {"label": 1, "probability": 0.9, "predicted": 1},
        {"label": 0, "probability": 0.1, "predicted": 0},
    ]
    inverted = [
        {"label": 1, "probability": 0.1, "predicted": 0},
        {"label": 0, "probability": 0.9, "predicted": 1},
    ]
    assert auc(perfect) == pytest.approx(1.0)
    assert auc(inverted) == pytest.approx(0.0)
    assert brier_score(perfect) == pytest.approx(0.01)
    assert false_positive_rate(perfect) == 0.0
    assert false_positive_rate(inverted) == 1.0


def test_auc_handles_ties():
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    from calibrate import auc

    tied = [
        {"label": 1, "probability": 0.5, "predicted": 1},
        {"label": 0, "probability": 0.5, "predicted": 0},
    ]
    assert auc(tied) == pytest.approx(0.5)


def test_auc_is_nan_without_both_classes():
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    from calibrate import auc

    assert math.isnan(auc([{"label": 1, "probability": 0.9, "predicted": 1}]))


def test_calibration_script_runs_end_to_end(tmp_path):
    png = tmp_path / "reliability.png"
    csv_path = tmp_path / "predictions.csv"
    completed = subprocess.run(
        [
            sys.executable, str(BACKEND_ROOT / "scripts" / "calibrate.py"),
            "--reliability-png", str(png),
            "--csv", str(csv_path),
            "--no-suggest",
        ],
        cwd=str(BACKEND_ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr
    assert "Brier score" in completed.stdout
    assert "AUC" in completed.stdout
    assert png.exists() and png.stat().st_size > 1000
    assert csv_path.exists() and "case-01-server-status-leak" in csv_path.read_text(encoding="utf-8")


def test_labelled_corpus_separates_the_two_classes():
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    from calibrate import auc, brier_score, false_positive_rate, load_cases, predict

    cases = load_cases(CORPUS_PATH)
    rows = [predict(case, 0.1, DEFAULT_CONFLICT_THRESHOLD) for case in cases]
    assert false_positive_rate(rows) == 0.0, "engine must not attribute any negative case"
    assert auc(rows) >= 0.9
    assert brier_score(rows) < 0.2
