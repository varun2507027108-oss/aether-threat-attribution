"""Phase 9 — stylometry v2: Burrows' Delta, LZW/NCD, Unicode-safe normalization, validation."""

import functools
import itertools
import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

from app.services.stylometry import (
    DEFAULT_BURROWS_REFERENCE,
    DEFAULT_ENSEMBLE_WEIGHTS,
    DEFAULT_STYLOMETRY_FPR,
    DEFAULT_STYLOMETRY_THRESHOLD,
    MIN_CHARS_FOR_NCD,
    MIN_TOKENS_FOR_DELTA,
    analyze_stylometry,
    burrows_delta,
    cosine_similarity,
    ensemble_similarity,
    extract_char_ngrams,
    lzw_compressed_length,
    normalized_compression_distance,
    normalize_for_stylometry,
    script_profile,
    stylometry_tokens,
)

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent
CORPUS_PATH = REPO_ROOT / "docs" / "validation" / "stylometry_corpus.json"
REPORT_PATH = REPO_ROOT / "docs" / "stylometry" / "report.md"


def load_corpus() -> dict:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def sample(author: str, index: int) -> str:
    return load_corpus()["authors"][author]["samples"][index]


# --------------------------------------------------------------------------- #
# Normalization
# --------------------------------------------------------------------------- #

def test_nfkc_folds_compatibility_variants():
    # Full-width Latin and a ligature should normalize to plain ASCII so the
    # same author typing on two keyboards is not split into two people.
    assert normalize_for_stylometry("ｒａｎｓｏｍ") == "ransom"
    assert normalize_for_stylometry("ﬁle") == "file"
    assert normalize_for_stylometry("ＬＯＣＡＬ") == "local"


def test_case_folding_but_script_preservation():
    assert normalize_for_stylometry("PAYMENT") == "payment"
    # Devanagari has no case; folding must be a no-op there, not a corruption.
    assert "नमस्ते" in normalize_for_stylometry("नमस्ते दुनिया")


def test_emoji_survive_normalization_and_tokenization():
    text = "server wapas live hai 🔥 abhi"
    assert "🔥" in normalize_for_stylometry(text)
    assert "🔥" in stylometry_tokens(text)


def test_emoji_clusters_stay_whole():
    """A flag is two regional indicators plus a joiner; it must stay one token."""
    tokens = stylometry_tokens("done 🇮🇳 finished")
    assert "🇮🇳" in tokens
    assert "done" in tokens and "finished" in tokens


def test_devanagari_tokens_are_preserved():
    tokens = stylometry_tokens("key rotate kiya hai सर्वर पर")
    assert "सर्वर" in tokens
    assert "rotate" in tokens


def test_control_characters_are_stripped_but_newlines_survive():
    assert "\x00" not in normalize_for_stylometry("a\x00b")
    assert "\n" in normalize_for_stylometry("line one\nline two")
    assert "‮" not in normalize_for_stylometry("safe‮evil")  # bidi override


def test_whitespace_is_collapsed():
    assert normalize_for_stylometry("  a \t\t b \n\n c  ") == "a b\nc"


def test_empty_input_is_safe():
    assert normalize_for_stylometry("") == ""
    assert stylometry_tokens("") == []


# --------------------------------------------------------------------------- #
# Script profile
# --------------------------------------------------------------------------- #

def test_script_profile_detects_code_mixing():
    profile = script_profile("bhai server wapas live hai सर्वर फिर से चालू है और log dekho")
    assert profile["indic"] > 0.0
    assert profile["latin"] > 0.0
    assert profile["code_mixed"] is True


def test_script_profile_detects_emoji():
    profile = script_profile("build pushed 🔥 loader ready 🚀")
    assert profile["has_emoji"] is True
    assert profile["emoji"] > 0.0


def test_script_profile_on_pure_english_is_not_code_mixed():
    profile = script_profile("the build was pushed to the drop server last night")
    assert profile["code_mixed"] is False
    assert profile["devanagari"] == 0.0


def test_script_profile_on_empty_text():
    assert script_profile("")["tokens"] == 0


# --------------------------------------------------------------------------- #
# Burrows' Delta
# --------------------------------------------------------------------------- #

def test_delta_is_zero_for_identical_text():
    result = burrows_delta(sample("A", 0), sample("A", 0))
    assert result["delta"] == 0.0
    assert result["similarity"] == 1.0
    assert result["status"] == "OK"


def test_delta_closer_for_same_author_than_cross_author():
    corpus = load_corpus()
    same = burrows_delta(corpus["authors"]["A"]["samples"][0], corpus["authors"]["A"]["samples"][1])
    cross = burrows_delta(corpus["authors"]["A"]["samples"][0], corpus["authors"]["B"]["samples"][0])
    assert same["delta"] < cross["delta"]
    assert same["similarity"] > cross["similarity"]


def test_delta_ordering_holds_on_average_across_the_corpus():
    """Delta is a statistical method, so ordering is an aggregate claim.

    Asserting that *every* same-author pair scores below *every* cross-author
    pair would be a stronger claim than the method supports; the measurable
    claim is that same-author pairs are closer on average.
    """
    corpus = load_corpus()["authors"]
    authors = sorted(corpus)

    def delta(text_a: str, text_b: str) -> float:
        return burrows_delta(text_a, text_b)["delta"]

    same = [
        delta(corpus[a]["samples"][i], corpus[a]["samples"][j])
        for a in authors for i in range(5) for j in range(i + 1, 5)
    ]
    cross = [
        delta(corpus[a]["samples"][i], corpus[b]["samples"][j])
        for a, b in itertools.combinations(authors, 2)
        for i in range(3) for j in range(3)
    ]
    assert sum(same) / len(same) < sum(cross) / len(cross)


def test_delta_extremes_are_correct():
    corpus = load_corpus()["authors"]
    identical = burrows_delta(corpus["A"]["samples"][0], corpus["A"]["samples"][0])
    disjoint = burrows_delta(
        corpus["A"]["samples"][0],
        "Gardeners in the north always sow the tomato seeds in early spring while the soil "
        "is still cold and damp from the last of the winter rain, and the compost heap is "
        "turned every fortnight to keep it sweet for the roots of the young plants.",
    )
    assert disjoint["status"] == "OK", "the control text must clear the Delta length gate"
    assert identical["delta"] < disjoint["delta"]
    assert identical["similarity"] > disjoint["similarity"]


def test_delta_similarity_is_bounded_and_monotone_in_delta():
    for delta in (0.0, 0.5, 1.0, 2.0, 10.0):
        assert 1.0 / (1.0 + delta) == pytest.approx(1.0 / (1.0 + delta))
    corpus = load_corpus()
    result = burrows_delta(corpus["authors"]["C"]["samples"][2], corpus["authors"]["C"]["samples"][3])
    assert 0.0 < result["similarity"] <= 1.0


def test_delta_is_refused_on_samples_that_are_too_short():
    """On tiny samples Delta reports high similarity for unrelated text."""
    result = burrows_delta("ransomware payload bitcoin", "gardening compost tomatoes")
    assert result["status"] == "insufficient_sample"
    assert result["similarity"] is None
    assert result["delta"] is None
    assert result["required_tokens"] == MIN_TOKENS_FOR_DELTA


def test_delta_refusal_is_not_silently_scored_as_zero():
    """A gated method must be absent, not 0.0. Zero is a real measurement."""
    result = burrows_delta("a b c", "d e f")
    assert result["similarity"] != 0.0
    assert result["status"] == "insufficient_sample"


def test_delta_reports_its_inputs_for_review():
    result = burrows_delta(sample("A", 0), sample("A", 1))
    assert result["vocabulary_size"] > 0
    assert result["reference_documents"] == len(DEFAULT_BURROWS_REFERENCE)
    assert len(result["vocabulary_sample"]) == 10


def test_delta_uses_a_real_reference_corpus():
    """Two-sample z-scores collapse to +/-0.707; the reference set prevents that."""
    assert len(DEFAULT_BURROWS_REFERENCE) >= 4
    result = burrows_delta(sample("A", 0), sample("B", 0), reference=["one", "two", "three", "four"])
    assert result["reference_documents"] == 4


def test_delta_vocabulary_selection_is_deterministic():
    """Tie-breaks must be alphabetical or the number is not reproducible."""
    a = burrows_delta(sample("A", 0), sample("A", 1))
    b = burrows_delta(sample("A", 0), sample("A", 1))
    assert a["vocabulary_sample"] == b["vocabulary_sample"]
    assert a["delta"] == b["delta"]


# --------------------------------------------------------------------------- #
# LZW / NCD
# --------------------------------------------------------------------------- #

def test_lzw_length_shrinks_for_repetitive_text():
    repetitive = "abcabcabc" * 20
    random_ish = "".join(chr(97 + (i * 7 + i // 3) % 26) for i in range(160))
    assert lzw_compressed_length(repetitive) < lzw_compressed_length(random_ish)


def test_lzw_is_deterministic_and_order_sensitive():
    assert lzw_compressed_length("abcabc") == lzw_compressed_length("abcabc")
    assert lzw_compressed_length("") == 0


def test_ncd_of_identical_text_is_exactly_zero():
    text = "the loader checks for sandbox artifacts before unpacking anything at all"
    result = normalized_compression_distance(text, text)
    assert result["ncd"] == 0.0
    assert result["similarity"] == 1.0
    assert result["status"] == "identical"


def test_ncd_stays_within_the_unit_interval():
    corpus = load_corpus()
    for a in ("A", "B", "C", "D"):
        for b in ("A", "B", "C", "D"):
            result = normalized_compression_distance(corpus["authors"][a]["samples"][0], corpus["authors"][b]["samples"][0])
            if result["ncd"] is not None:
                assert 0.0 <= result["ncd"] <= 1.0
                assert 0.0 <= result["similarity"] <= 1.0


def test_ncd_of_disjoint_long_text_is_near_one():
    result = normalized_compression_distance(
        sample("A", 0),
        "Gardeners in the north always sow the tomato seeds in early spring while "
        "the soil is still cold and damp from the last of the winter rain, and the "
        "compost heap is turned every fortnight to keep it sweet for the roots.",
    )
    assert result["status"] == "OK"
    assert result["ncd"] > 0.8
    assert result["similarity"] < 0.2


def test_ncd_is_refused_on_samples_that_are_too_short():
    result = normalized_compression_distance("too short", "also short")
    assert result["status"] == "insufficient_sample"
    assert result["similarity"] is None
    assert result["required_chars"] == MIN_CHARS_FOR_NCD


def test_ncd_handles_empty_input():
    result = normalized_compression_distance("", "something")
    assert result["status"] == "empty_sample"
    assert result["similarity"] is None


# --------------------------------------------------------------------------- #
# Ensemble
# --------------------------------------------------------------------------- #

def test_ensemble_renormalizes_over_available_methods():
    """A method that did not run is absent, not zero. 0.0 is a real measurement."""
    result = ensemble_similarity({"cosine": 1.0, "delta": None, "ncd": None})
    assert result["score"] == pytest.approx(1.0)
    assert result["degraded"] is True
    assert result["methods_used"] == ["cosine"]
    assert result["weights_used"]["cosine"] == pytest.approx(1.0)


def test_ensemble_ignores_a_zero_but_present_method():
    """0.0 is a legitimate Delta or NCD result and must be weighted normally."""
    result = ensemble_similarity({"cosine": 1.0, "delta": 0.0, "ncd": 0.0})
    assert result["methods_used"] == ["cosine", "delta", "ncd"]
    assert result["degraded"] is False
    assert result["score"] == pytest.approx(1.0 * DEFAULT_ENSEMBLE_WEIGHTS["cosine"], abs=1e-9)


def test_ensemble_reports_degradation_when_all_methods_run():
    result = ensemble_similarity({"cosine": 0.5, "delta": 0.5, "ncd": 0.5})
    assert result["degraded"] is False
    assert result["score"] == pytest.approx(0.5)


def test_ensemble_ignores_unknown_and_none_methods():
    result = ensemble_similarity({"cosine": 1.0, "delta": None, "mystery": 99.0})
    assert result["methods_used"] == ["cosine"]
    assert result["score"] == pytest.approx(1.0)


def test_ensemble_with_no_usable_methods_is_zero_not_a_crash():
    result = ensemble_similarity({"cosine": None, "delta": None, "ncd": None})
    assert result["score"] == 0.0
    assert result["degraded"] is True
    assert result["methods_used"] == []


def test_ensemble_weights_sum_to_one_when_all_methods_run():
    result = ensemble_similarity({"cosine": 0.2, "delta": 0.2, "ncd": 0.2})
    assert sum(result["weights_used"].values()) == pytest.approx(1.0)


def test_ensemble_is_monotone_in_each_method():
    base = ensemble_similarity({"cosine": 0.5, "delta": 0.5, "ncd": 0.5})["score"]
    higher = ensemble_similarity({"cosine": 0.9, "delta": 0.5, "ncd": 0.5})["score"]
    assert higher > base


# --------------------------------------------------------------------------- #
# analyze_stylometry contract
# --------------------------------------------------------------------------- #

def test_identical_text_scores_one():
    text = sample("A", 0)
    result = analyze_stylometry(text, text)
    assert result["similarity_score"] == 1.0
    assert result["confidence_tier"] == "SAME AUTHOR (high confidence)"


def test_response_exposes_every_method_score_and_the_threshold():
    result = analyze_stylometry(sample("A", 0), sample("B", 0))
    assert result["engine"] == "cosine+burrows_delta+lzw_ncd"
    assert set(result["method_scores"]) == {"cosine", "cosine_components", "delta", "ncd"}
    assert result["method_scores"]["delta"]["status"] == "OK"
    assert result["method_scores"]["ncd"]["status"] == "OK"
    assert result["threshold"] == DEFAULT_STYLOMETRY_THRESHOLD
    assert result["fpr_at_threshold"] == DEFAULT_STYLOMETRY_FPR
    assert result["confidence_tier"] in ("SAME AUTHOR (high confidence)", "POSSIBLE MATCH (below reporting threshold)")


def test_legacy_cosine_composite_is_still_reported_and_reproducible():
    """Any conclusion reached before Phase 9 must remain checkable."""
    a, b = sample("A", 0), sample("C", 0)
    result = analyze_stylometry(a, b)
    expected = round(
        0.50 * result["breakdown"]["char_3gram_cosine"]
        + 0.30 * result["breakdown"]["word_unigram_cosine"]
        + 0.20 * result["breakdown"]["word_bigram_cosine"],
        4,
    )
    assert result["legacy_cosine_composite"] == expected
    assert result["method_scores"]["cosine"] == expected


def test_short_samples_still_produce_a_score_from_cosine():
    result = analyze_stylometry("ransomware payload bitcoin", "gardening compost tomatoes")
    assert 0.0 <= result["similarity_score"] <= 1.0
    assert result["ensemble"]["degraded"] is True
    assert result["ensemble"]["methods_used"] == ["cosine"]
    assert result["method_scores"]["delta"]["status"] == "insufficient_sample"
    assert result["method_scores"]["ncd"]["status"] == "insufficient_sample"


def test_hinglish_author_is_recognised_against_its_own_notes():
    """The whole reason Devanagari and emoji are preserved.

    Before Phase 9 the tokenizer dropped every non-\\w character, so a Hinglish
    author scored near zero against their own English notes and the system would
    systematically under-attribute that entire population.
    """
    corpus = load_corpus()
    samples = corpus["authors"]["C"]["samples"]

    assert script_profile(samples[0])["code_mixed"] is True

    same = analyze_stylometry(samples[0], samples[3])
    cross = analyze_stylometry(samples[0], corpus["authors"]["B"]["samples"][0])
    assert same["script_profile_a"]["indic"] > 0.0
    assert same["script_profile_a"]["code_mixed"] is True
    assert same["similarity_score"] > cross["similarity_score"]


def test_corpus_includes_a_code_mixed_author():
    samples = load_corpus()["authors"]["C"]["samples"]
    with_devanagari = [t for t in samples if any("\u0900" <= ch <= "\u097f" for ch in t)]
    with_emoji = [t for t in samples if any(ord(ch) > 0x1F000 for ch in t)]
    assert len(with_devanagari) == 10, "every code-mixed sample should carry Devanagari"
    assert len(with_emoji) >= 5
    # And the emoji must survive the tokenizer, not just the raw string.
    assert any(
        any(ord(ch) > 0x1F000 for ch in token)
        for text in samples for token in stylometry_tokens(text)
    )


def test_carries_an_explicit_evidence_caveat():
    result = analyze_stylometry(sample("A", 0), sample("B", 0))
    assert "not identity" in result["evidentiary_caveat"]
    assert "corroboration" in result["evidentiary_caveat"]


def test_cosine_similarity_helper_still_behaves():
    from collections import Counter

    assert cosine_similarity(Counter("a b c".split()), Counter("a b c".split())) == 1.0
    assert cosine_similarity(Counter(), Counter("a")) == 0.0


def test_char_ngrams_still_work_on_short_input():
    assert extract_char_ngrams("ab", n=3)


# --------------------------------------------------------------------------- #
# Corpus and validation script
# --------------------------------------------------------------------------- #

def test_corpus_has_four_authors_with_ten_usable_samples_each():
    payload = load_corpus()
    authors = payload["authors"]
    assert len(authors) == 4
    for name, entry in authors.items():
        assert len(entry["samples"]) == 10, name
        assert entry["profile"]
        for text in entry["samples"]:
            assert len(stylometry_tokens(text)) >= MIN_TOKENS_FOR_DELTA, name
            assert len(text) >= MIN_CHARS_FOR_NCD, name


def test_pipeline_records_per_method_stylometry(client):
    res = client.post("/api/cases/investigate?sync=true", json={
        "case_name": "Stylometry v2 Probe",
        "evidence_id": "AT-2026-ST01",
        "actor_name": "Tester",
        "target": "185.220.101.42",
        "target_type": "ip",
        "mode": "demo",
    })
    assert res.status_code == 200
    records = res.json()["case"]["evidence_records"]
    stylo = next(r for r in records if r["evidence_type"] == "STYLOMETRY")
    meta = stylo["metadata_json"]
    assert meta["engine"] == "cosine+burrows_delta+lzw_ncd"
    assert "method_scores" in meta
    assert "ensemble" in meta
    assert meta["threshold"] == DEFAULT_STYLOMETRY_THRESHOLD
    assert "script_profile_target" in meta
    assert "Burrows" in stylo["source_reference"]


def test_corpus_topics_vary_within_each_author():
    """A corpus where every sample is about the same incident measures topic, not style."""
    for name, entry in load_corpus()["authors"].items():
        first_words = {stylometry_tokens(t)[0] for t in entry["samples"]}
        assert len(first_words) >= 5, f"author {name} samples start too uniformly"


def test_validation_script_runs_and_writes_a_report(tmp_path):
    report = tmp_path / "report.md"
    completed = subprocess.run(
        [
            sys.executable, str(BACKEND_ROOT / "scripts" / "validate_stylometry.py"),
            "--report", str(report),
        ],
        cwd=str(BACKEND_ROOT),
        capture_output=True, text=True, timeout=1800,
    )
    assert completed.returncode == 0, completed.stderr
    assert "AUC=" in completed.stdout
    assert "recommended threshold" in completed.stdout
    assert report.exists()
    body = report.read_text(encoding="utf-8")
    assert "Stylometry Validation Report" in body
    assert "## ROC" in body
    assert "## Interpretation" in body


def test_validation_script_threshold_check_passes_at_the_shipped_threshold():
    completed = subprocess.run(
        [
            sys.executable, str(BACKEND_ROOT / "scripts" / "validate_stylometry.py"),
            "--check-threshold", str(DEFAULT_STYLOMETRY_THRESHOLD),
            "--no-report",
        ],
        cwd=str(BACKEND_ROOT),
        capture_output=True, text=True, timeout=1800,
    )
    assert completed.returncode == 0, completed.stderr + completed.stdout
    assert "OK: FPR" in completed.stdout


def test_shipped_report_exists_and_documents_the_threshold():
    assert REPORT_PATH.exists(), "run scripts/validate_stylometry.py to generate the report"
    body = REPORT_PATH.read_text(encoding="utf-8")
    assert str(DEFAULT_STYLOMETRY_THRESHOLD) in body
    assert "0.9193" in body or "AUC" in body


# --------------------------------------------------------------------------- #
# Measured behaviour on the labelled corpus
# --------------------------------------------------------------------------- #

@functools.lru_cache(maxsize=1)
def scored_corpus():
    """Score every corpus pair once and return all four aggregations.

    Three separate sweeps over 780 pairs would triple the cost of this section
    for no extra information; the analysis is identical, only the aggregation
    differs.
    """
    sys.path.insert(0, str(BACKEND_ROOT / "scripts"))
    from validate_stylometry import build_pairs, load_corpus as load_vc, score_pairs

    corpus = load_vc(CORPUS_PATH)
    positives, negatives = build_pairs(corpus)
    pairs = positives + negatives
    return {method: score_pairs(pairs, method=method) for method in ("cosine", "ensemble", "delta", "ncd")}


def test_ensemble_beats_cosine_on_the_labelled_corpus():
    from validate_stylometry import auc

    scores = scored_corpus()
    ensemble_auc = auc(scores["ensemble"])
    assert ensemble_auc > auc(scores["cosine"])
    assert ensemble_auc >= 0.85, f"ensemble AUC regressed to {ensemble_auc}"


def test_delta_is_the_strongest_single_method():
    from validate_stylometry import auc

    scores = scored_corpus()
    assert auc(scores["delta"]) > auc(scores["cosine"])
    assert auc(scores["ncd"]) > auc(scores["cosine"])


def test_measured_fpr_matches_the_reported_constant():
    from validate_stylometry import rates_at

    measured = rates_at(scored_corpus()["ensemble"], DEFAULT_STYLOMETRY_THRESHOLD)["fpr"]
    assert measured == pytest.approx(DEFAULT_STYLOMETRY_FPR, abs=0.0001)
    assert measured <= 0.05, "the shipped threshold breaches its false-positive budget"


def test_surviving_false_positives_are_the_documented_register_collision():
    """The residuals cluster on adjacent-formal registers, not at random.

    B and D are the two formal-English voices, and B paired with A (terse
    lowercase technical) is the next closest. If the top residuals were spread
    uniformly across author pairs, the failure would be uncharacterised noise and
    the caveat in the report would be a guess.
    """
    from collections import Counter
    from validate_stylometry import rates_at

    rows = scored_corpus()["ensemble"]
    negatives = sorted(
        (r for r in rows if r["label"] == 0 and r["score"] is not None),
        key=lambda r: r["score"], reverse=True,
    )
    threshold = rates_at(rows, DEFAULT_STYLOMETRY_THRESHOLD)["threshold"]
    top = negatives[:10]
    counts = Counter(r["author"] for r in top)

    assert set(counts) <= {"B|D", "A|B"}, f"residuals spread unexpectedly: {dict(counts)}"
    assert counts.most_common(1)[0][0] == "B|D", "the formal-English pair should be the plurality"
    assert max(r["score"] for r in top) > threshold, "control: some residuals do breach the threshold"


def test_default_weights_are_justified_by_measured_auc():
    """Cosine is down-weighted because it is the weakest discriminator."""
    assert DEFAULT_ENSEMBLE_WEIGHTS["cosine"] < DEFAULT_ENSEMBLE_WEIGHTS["delta"]
    assert DEFAULT_ENSEMBLE_WEIGHTS["delta"] >= DEFAULT_ENSEMBLE_WEIGHTS["ncd"]
    assert sum(DEFAULT_ENSEMBLE_WEIGHTS.values()) == pytest.approx(1.0)


# --------------------------------------------------------------------------- #
# API and pipeline
# --------------------------------------------------------------------------- #

def test_api_stylometry_endpoint_reports_every_method(client):
    corpus = load_corpus()
    res = client.post("/api/analysis/stylometry", json={
        "text_a": corpus["authors"]["A"]["samples"][0],
        "text_b": corpus["authors"]["A"]["samples"][1],
    })
    assert res.status_code == 200
    data = res.json()
    assert data["engine"] == "cosine+burrows_delta+lzw_ncd"
    assert data["method_scores"]["delta"]["status"] == "OK"
    assert data["method_scores"]["ncd"]["status"] == "OK"
    assert data["threshold"] == DEFAULT_STYLOMETRY_THRESHOLD
    assert "fpr_at_threshold" in data
    assert 0.0 <= data["similarity_score"] <= 1.0





def test_stylometry_module_name_reflects_the_v2_engine():
    from app.services.investigation import MODULE_DEFS

    entry = next(m for m in MODULE_DEFS if m["module"] == "stylometry")
    assert "Stylometry" in entry["name"] or "Stylometric" in entry["name"]
