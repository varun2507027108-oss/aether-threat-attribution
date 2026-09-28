"""Stylometry analysis service for Project AETHER.

Compares suspect text samples using three complementary views of authorial
style, then fuses them into one reportable score:

1. **Cosine similarity** over character and word n-grams (existing). Robust for
   short forum snippets, but blind to function-word habits.
2. **Burrows' Delta** over z-scored most-frequent-word vectors. Targets the
   single strongest authorial signal in the literature: *how often* a writer
   uses common words, independent of topic. Two ransom notes on the same
   subject can share almost no vocabulary and still be obviously the same
   author; Delta catches that and cosine cannot.
3. **Normalized Compression Distance** via LZW. Measures structural
   redundancy, so it notices phrasing habits that share no n-grams.

Normalization preserves Devanagari, emoji, and code-mixed Hinglish tokens. The
earlier pipeline dropped emoji at the token boundary and would have scored a
Hinglish writer as a different person from their own English notes, which is a
systematic bias against exactly the population this system is built to serve.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# --------------------------------------------------------------------------- #
# Normalization and tokenization (Phase 9)
# --------------------------------------------------------------------------- #

# Token pattern, evaluated in order. Emoji come first so a ZWJ sequence or a
# regional-indicator flag stays one token instead of shattering into fragments.
# Devanagari and the other Indic blocks are matched explicitly. The previous
# pipeline used \b\w+\b, which happens to keep Devanagari but silently discards
# every emoji, flag, and variation selector.
_TOKEN_RE = re.compile(
    r"[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\u200D\uFE0F]+"
    r"|[\u0900-\u097F\u0980-\u0DFF\u0A00-\u0A7F\u0B00-\u0B7F]+"
    r"|[a-z0-9_]+"
)

_INDIC_RE = re.compile(r"[\u0900-\u097F\u0980-\u0DFF\u0A00-\u0A7F\u0B00-\u0B7F]+")
_EMOJI_RE = re.compile(r"[\U0001F000-\U0001FAFF\u2600-\u27BF\u2B00-\u2BFF\u200D\uFE0F]")

DEFAULT_ENSEMBLE_WEIGHTS: Dict[str, float] = {
    "cosine": 0.10,
    "delta": 0.50,
    "ncd": 0.40,
}

# FPR target for a reportable stylometric lead. 0.05 is the default because a
# false positive here means naming the wrong person in a court filing.
DEFAULT_STYLOMETRY_THRESHOLD = 0.39

# Measured on the bundled corpus (docs/validation/stylometry_corpus.json,
# 4 authors x 10 samples -> 180 same-author and 600 cross-author pairs):
#   AUC 0.9138, FPR 0.0467 at the shipped threshold, TPR 0.4722.
# The surviving false positives are almost entirely the B|D pair, i.e. the two
# formal-English registers, which is the expected and documented failure mode.
# Recomputed by scripts/validate_stylometry.py; asserted by test_stylometry_v2.
DEFAULT_STYLOMETRY_FPR = 0.0467

# Minimum sample size for each method to be trusted. Burrows' Delta needs a
# stable most-frequent-word profile; below a few dozen tokens the z-scores are
# dominated by sampling noise and the method reports *high* similarity for
# completely unrelated texts, which is worse than reporting nothing. LZW
# compression distance needs enough text for dictionary sharing to be
# measurable. When a method is gated it returns similarity=None and the
# ensemble renormalizes over the methods that did run, reporting degraded=True.
MIN_TOKENS_FOR_DELTA = 40
MIN_CHARS_FOR_NCD = 80


def _is_invisible(ch: str) -> bool:
    """True for characters carrying no style signal and therefore only noise."""
    return unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn")


def normalize_for_stylometry(text: str) -> str:
    """Normalize text for style comparison without destroying its character.

    NFKC folds compatibility variants (full-width Latin, ligatures) so notes
    typed on different keyboards compare fairly. Case is folded; Devanagari has
    no case so folding is a no-op there, which is exactly what we want for
    Hinglish. Whitespace is collapsed, but token content is never stripped.
    """
    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    # Keep newlines and tabs long enough for sentence splitting, drop the rest.
    normalized = "".join(ch for ch in normalized if ch in "\n\t" or not _is_invisible(ch))
    normalized = normalized.lower()
    collapsed = re.sub(r"[ \t]+", " ", normalized)
    return re.sub(r"\n{2,}", "\n", re.sub(r"[ \t]*\n[ \t]*", "\n", collapsed)).strip()


def stylometry_tokens(text: str) -> List[str]:
    """Tokenize into style-bearing units, preserving emoji and Indic scripts."""
    return _TOKEN_RE.findall(normalize_for_stylometry(text))


def script_profile(text: str) -> Dict[str, Any]:
    """Report the script mix of a sample.

    Hinglish and other code-mixed writing is a first-class case here: a system
    that dropped Devanagari would report a Hinglish author as dissimilar to
    their own notes, systematically under-attributing exactly the population
    this system exists to serve.
    """
    tokens = stylometry_tokens(text)
    if not tokens:
        return {"tokens": 0, "latin": 0.0, "indic": 0.0, "emoji": 0.0, "code_mixed": False, "has_emoji": False}

    indic = emoji = 0
    for token in tokens:
        if _EMOJI_RE.search(token):
            emoji += 1
        elif _INDIC_RE.fullmatch(token):
            indic += 1

    total = len(tokens)
    return {
        "tokens": total,
        "latin": round((total - indic - emoji) / total, 4),
        "indic": round(indic / total, 4),
        "devanagari": round(indic / total, 4),
        "emoji": round(emoji / total, 4),
        "code_mixed": (indic / total) > 0.05 and ((total - indic - emoji) / total) > 0.05,
        "has_emoji": emoji > 0,
    }


def _clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def tokenize_words(text: str) -> List[str]:
    """Tokenize into lowercase words, preserving emoji and Indic scripts."""
    return stylometry_tokens(text)


def tokenize_sentences(text: str) -> List[str]:
    """Split text into sentences based on standard punctuation."""
    sentences = re.split(r"[.!?]+(?:\s+|$)", text.strip())
    return [s.strip() for s in sentences if s.strip()]


def extract_char_ngrams(text: str, n: int = 3) -> Counter[str]:
    """Extract character n-grams from normalized text."""
    normalized = _clean_text(text.lower())
    if len(normalized) < n:
        return Counter([normalized]) if normalized else Counter()
    return Counter(normalized[i : i + n] for i in range(len(normalized) - n + 1))


def extract_word_ngrams(tokens: List[str], n: int = 2) -> Counter[str]:
    """Extract word n-grams from tokenized words."""
    if len(tokens) < n:
        return Counter([" ".join(tokens)]) if tokens else Counter()
    return Counter(" ".join(tokens[i : i + n]) for i in range(len(tokens) - n + 1))


def cosine_similarity(counter_a: Counter[str], counter_b: Counter[str]) -> float:
    """Compute exact cosine similarity between two frequency Counters."""
    if not counter_a or not counter_b:
        return 0.0

    intersection = set(counter_a.keys()) & set(counter_b.keys())
    dot_product = sum(counter_a[k] * counter_b[k] for k in intersection)

    norm_a = math.sqrt(sum(v * v for v in counter_a.values()))
    norm_b = math.sqrt(sum(v * v for v in counter_b.values()))

    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0

    return round(float(dot_product / (norm_a * norm_b)), 4)


def compute_lexical_metrics(text: str) -> Dict[str, Any]:
    """Extract forensic stylometric markers from a single text."""
    words = tokenize_words(text)
    sentences = tokenize_sentences(text)

    total_words = len(words)
    total_unique = len(set(words))
    ttr = round(total_unique / total_words, 4) if total_words > 0 else 0.0

    avg_sentence_len = round(total_words / len(sentences), 2) if sentences else 0.0

    # Punctuation counts
    punct_patterns = {
        "semicolons": r";",
        "colons": r":",
        "hyphens": r"-",
        "commas": r",",
        "exclamations": r"!",
        "questions": r"\?",
        "ellipses": r"\.{3}|…",
    }
    punct_counts = {
        name: len(re.findall(pattern, text))
        for name, pattern in punct_patterns.items()
    }

    # Casing characteristics
    letters = [c for c in text if c.isalpha()]
    total_letters = len(letters)
    uppercase_ratio = (
        round(sum(1 for c in letters if c.isupper()) / total_letters, 4)
        if total_letters > 0
        else 0.0
    )

    return {
        "word_count": total_words,
        "unique_words": total_unique,
        "type_token_ratio": ttr,
        "sentence_count": len(sentences),
        "avg_sentence_length": avg_sentence_len,
        "punctuation_counts": punct_counts,
        "uppercase_ratio": uppercase_ratio,
    }


# --------------------------------------------------------------------------- #
# Burrows' Delta (Phase 9)
# --------------------------------------------------------------------------- #

# A small neutral background corpus. Burrows' Delta z-scores each text against a
# *population*; computed over only the two compared texts, the standard
# deviation comes from two points and every z collapses to +/-0.707, destroying
# all magnitude information and making the method a relabelled cosine. A
# background set is what makes Delta meaningful, so one is bundled.
DEFAULT_BURROWS_REFERENCE: Tuple[str, ...] = (
    "The committee reviewed the quarterly figures and agreed that the shortfall "
    "would require an additional review before the end of the financial year.",
    "Researchers published a study describing how the measurement was carried "
    "out, together with the limitations that readers should consider when they "
    "compare it with earlier work in the same area of the literature.",
    "Please make sure that the file has been saved and that the settings have "
    "been applied before you close the application, otherwise the changes will "
    "be lost and you will need to start again from the beginning.",
    "There are several reasons why this approach is preferred: it is simpler to "
    "implement, it is easier to explain to people who are new to the subject, "
    "and it has been shown to work well in practice over a number of years.",
    "He said that the plan would not work, but she pointed out that most of the "
    "problems they had seen in the past came from a lack of time rather than a "
    "lack of money or a lack of people to do the work with.",
    "The system records each request, stores the result, and returns a response "
    "that includes a unique identifier so that the caller can refer to the same "
    "operation again later if it needs to be repeated or inspected.",
)


def _most_frequent_words(token_lists: Sequence[Sequence[str]], vocab_size: int) -> List[str]:
    pooled: Counter[str] = Counter()
    for tokens in token_lists:
        pooled.update(tokens)
    # Ties broken alphabetically so the vocabulary is deterministic across runs.
    # A run-to-run tie-break would make Delta non-reproducible, which is fatal
    # for a number that ends up in an evidence statement.
    ranked = sorted(pooled.items(), key=lambda kv: (-kv[1], kv[0]))
    return [word for word, _ in ranked[:vocab_size]]


def burrows_delta(
    text_a: str,
    text_b: str,
    reference: Optional[Iterable[str]] = None,
    vocab_size: int = 50,
) -> Dict[str, Any]:
    """Compute Burrows' Delta between two samples.

    Counts are length-normalized to relative frequencies before z-scoring so a
    500-word note and a 50-word note are comparable. The response includes the
    vocabulary size and the number of reference documents, because a reviewer
    asking "what was this computed from?" deserves a real answer.
    """
    tokens_a = stylometry_tokens(text_a)
    tokens_b = stylometry_tokens(text_b)
    reference_texts = list(reference) if reference is not None else list(DEFAULT_BURROWS_REFERENCE)
    reference_documents = len(reference_texts)

    if not tokens_a or not tokens_b:
        return {
            "delta": None,
            "similarity": None,
            "status": "insufficient_sample",
            "vocabulary_size": 0,
            "reference_documents": reference_documents,
            "reason": "one or both samples produced no tokens",
        }

    shortest = min(len(tokens_a), len(tokens_b))
    if shortest < MIN_TOKENS_FOR_DELTA:
        # Reporting a Delta here would be reporting noise: on very short samples
        # the method assigns high similarity to unrelated texts, which inverts
        # its own purpose.
        return {
            "delta": None,
            "similarity": None,
            "status": "insufficient_sample",
            "shortest_sample_tokens": shortest,
            "required_tokens": MIN_TOKENS_FOR_DELTA,
            "vocabulary_size": 0,
            "reference_documents": reference_documents,
            "reason": (
                f"shortest sample has {shortest} tokens; Burrows' Delta needs at least "
                f"{MIN_TOKENS_FOR_DELTA} for a stable most-frequent-word profile"
            ),
        }

    reference_tokens = [stylometry_tokens(text) for text in reference_texts]
    corpus = reference_tokens + [tokens_a, tokens_b]
    vocabulary = _most_frequent_words(corpus, vocab_size)

    if not vocabulary:
        return {
            "delta": None,
            "similarity": None,
            "status": "no_vocabulary",
            "vocabulary_size": 0,
            "reference_documents": reference_documents,
            "reason": "no vocabulary could be derived",
        }

    rows: List[List[float]] = []
    for tokens in corpus:
        total = len(tokens)
        counts = Counter(tokens)
        rows.append([counts[word] / total for word in vocabulary])

    n = len(rows)
    means = [sum(row[j] for row in rows) / n for j in range(len(vocabulary))]
    stds: List[float] = []
    for j in range(len(vocabulary)):
        variance = sum((row[j] - means[j]) ** 2 for row in rows) / n
        stds.append(math.sqrt(variance))

    def z_scores(row: List[float]) -> List[float]:
        return [
            (row[j] - means[j]) / stds[j] if stds[j] > 1e-12 else 0.0
            for j in range(len(vocabulary))
        ]

    z_a = z_scores(rows[-2])
    z_b = z_scores(rows[-1])
    delta = sum(abs(a - b) for a, b in zip(z_a, z_b)) / len(vocabulary)

    return {
        "delta": round(delta, 4),
        "similarity": round(1.0 / (1.0 + delta), 4),
        "status": "OK",
        "vocabulary_size": len(vocabulary),
        "vocabulary_sample": vocabulary[:10],
        "reference_documents": reference_documents,
    }


# --------------------------------------------------------------------------- #
# Normalized Compression Distance via LZW (Phase 9)
# --------------------------------------------------------------------------- #


def lzw_compressed_length(data: str) -> int:
    """Number of LZW phrase-list entries needed to encode ``data``.

    LZW is used rather than zlib because NCD is defined over a compressor that
    builds a *dictionary* the way an analyst reasons about recurring phrases,
    and because zlib's header bytes make distances on very short samples
    meaningless.
    """
    if not data:
        return 0

    dictionary: set = set(data)
    length = 1
    current = data[0]
    for char in data[1:]:
        candidate = current + char
        if candidate in dictionary:
            current = candidate
        else:
            dictionary.add(candidate)
            length += 1
            current = char
    return length


def normalized_compression_distance(text_a: str, text_b: str) -> Dict[str, Any]:
    """Compute Normalized Compression Distance using LZW.

    ``NCD(a, b) = (L(ab) - min(L(a), L(b))) / max(L(a), L(b))``

    The theoretical range is ``[0, 1 + 1/max]``, slightly above 1 for very short
    inputs, so the value is clamped to ``[0, 1]`` before conversion. Similarity
    is ``1 - NCD``.
    """
    a = normalize_for_stylometry(text_a)
    b = normalize_for_stylometry(text_b)
    if not a or not b:
        return {
            "ncd": None, "similarity": None, "status": "empty_sample",
            "length_a": 0, "length_b": 0, "length_ab": 0,
            "reason": "one or both samples were empty after normalization",
        }

    if a == b:
        # NCD(x, x) is not 0 under the raw definition: L(xx) exceeds L(x) by a
        # phrase or two, giving a raw distance of roughly 1/L(x). The distance
        # between a string and itself is zero, so short-circuit it. Without this
        # an identical sample caps out around 0.86 in the ensemble, which reads
        # as "probably not the same author" for a literal copy-paste.
        return {
            "ncd": 0.0, "similarity": 1.0, "status": "identical",
            "raw_ncd": 0.0,
            "length_a": lzw_compressed_length(a),
            "length_b": lzw_compressed_length(b),
            "length_ab": lzw_compressed_length(a + b),
        }

    shortest = min(len(a), len(b))
    if shortest < MIN_CHARS_FOR_NCD:
        return {
            "ncd": None, "similarity": None, "status": "insufficient_sample",
            "length_a": 0, "length_b": 0, "length_ab": 0,
            "shortest_sample_chars": shortest,
            "required_chars": MIN_CHARS_FOR_NCD,
            "reason": (
                f"shortest sample has {shortest} characters; LZW compression distance needs "
                f"at least {MIN_CHARS_FOR_NCD} for dictionary sharing to be measurable"
            ),
        }

    length_a = lzw_compressed_length(a)
    length_b = lzw_compressed_length(b)
    length_ab = lzw_compressed_length(a + b)

    denominator = max(length_a, length_b)
    if denominator == 0:
        return {
            "ncd": None, "similarity": None, "status": "degenerate",
            "length_a": length_a, "length_b": length_b, "length_ab": length_ab,
            "reason": "degenerate sample length",
        }

    raw = (length_ab - min(length_a, length_b)) / denominator
    ncd = max(0.0, min(1.0, raw))

    return {
        "ncd": round(ncd, 4),
        "similarity": round(1.0 - ncd, 4),
        "raw_ncd": round(raw, 4),
        "status": "OK",
        "length_a": length_a,
        "length_b": length_b,
        "length_ab": length_ab,
    }


# --------------------------------------------------------------------------- #
# Ensemble fusion
# --------------------------------------------------------------------------- #


def ensemble_similarity(
    method_scores: Dict[str, Optional[float]],
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Fuse per-method similarities into one score.

    Only methods that actually produced a score are counted, and the weights
    are renormalized over them, so a method that failed degrades the ensemble
    instead of dragging the score toward zero. The response names which methods
    were counted, because a score computed from a subset is a different claim
    than one computed from everything.
    """
    active_weights = dict(weights or DEFAULT_ENSEMBLE_WEIGHTS)
    contributing = {
        name: score
        for name, score in method_scores.items()
        if score is not None and name in active_weights
    }
    if not contributing:
        return {"score": 0.0, "methods_used": [], "weights_used": {}, "degraded": True}

    total_weight = sum(active_weights[name] for name in contributing)
    if total_weight <= 0:
        return {"score": 0.0, "methods_used": [], "weights_used": {}, "degraded": True}

    score = sum(contributing[name] * active_weights[name] for name in contributing) / total_weight
    return {
        "score": round(max(0.0, min(1.0, score)), 4),
        "methods_used": sorted(contributing),
        "weights_used": {name: round(active_weights[name] / total_weight, 4) for name in contributing},
        "degraded": len(contributing) < len(active_weights),
    }


def analyze_stylometry(
    text_a: str,
    text_b: str,
    weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """Perform comparative forensic stylometry between two texts.

    Reports all three method scores individually as well as the fused ensemble,
    because a single composite number invites the question "on what basis?" and
    the honest answer needs to be in the response rather than in a lab notebook.
    """
    words_a = stylometry_tokens(text_a)
    words_b = stylometry_tokens(text_b)

    # 1. Character 3-gram similarity (captures sub-word morphology and spelling quirks)
    char_3gram_sim = cosine_similarity(extract_char_ngrams(text_a, n=3), extract_char_ngrams(text_b, n=3))

    # 2. Word unigram similarity (vocabulary overlap)
    word_unigram_sim = cosine_similarity(Counter(words_a), Counter(words_b))

    # 3. Word bigram similarity (phrasal habits)
    word_bigram_sim = cosine_similarity(
        extract_word_ngrams(words_a, n=2), extract_word_ngrams(words_b, n=2)
    )

    # Legacy cosine composite. Retained because the investigation pipeline, the
    # API contract, and the scoring engine all consume `similarity_score`.
    cosine_composite = round(
        (0.50 * char_3gram_sim) + (0.30 * word_unigram_sim) + (0.20 * word_bigram_sim),
        4,
    )

    # 4. Burrows' Delta over function-word habits
    delta_res = burrows_delta(text_a, text_b)

    # 5. Normalized Compression Distance over phrasing redundancy
    ncd_res = normalized_compression_distance(text_a, text_b)

    ensemble = ensemble_similarity(
        {"cosine": cosine_composite, "delta": delta_res.get("similarity"), "ncd": ncd_res.get("similarity")},
        weights=weights,
    )

    metrics_a = compute_lexical_metrics(text_a)
    metrics_b = compute_lexical_metrics(text_b)
    shared_vocab = sorted(set(words_a) & set(words_b))

    return {
        # The ensemble is now the headline score. The legacy cosine composite is
        # still reported in full so any earlier conclusion remains reproducible.
        "similarity_score": ensemble["score"],
        "confidence_tier": (
            "SAME AUTHOR (high confidence)"
            if ensemble["score"] >= DEFAULT_STYLOMETRY_THRESHOLD
            else "POSSIBLE MATCH (below reporting threshold)"
        ),
        "threshold": DEFAULT_STYLOMETRY_THRESHOLD,
        "fpr_at_threshold": DEFAULT_STYLOMETRY_FPR,
        "engine": "cosine+burrows_delta+lzw_ncd",
        "ensemble": {
            "score": ensemble["score"],
            "methods_used": ensemble["methods_used"],
            "weights_used": ensemble["weights_used"],
            "degraded": ensemble["degraded"],
        },
        "method_scores": {
            "cosine": round(cosine_composite, 4),
            "cosine_components": {
                "char_3gram_cosine": char_3gram_sim,
                "word_unigram_cosine": word_unigram_sim,
                "word_bigram_cosine": word_bigram_sim,
            },
            "delta": delta_res,
            "ncd": ncd_res,
        },
        "breakdown": {
            "char_3gram_cosine": char_3gram_sim,
            "word_unigram_cosine": word_unigram_sim,
            "word_bigram_cosine": word_bigram_sim,
        },
        "legacy_cosine_composite": cosine_composite,
        "script_profile_a": script_profile(text_a),
        "script_profile_b": script_profile(text_b),
        "shared_tokens_count": len(shared_vocab),
        "shared_tokens_sample": shared_vocab[:15],
        "sample_a_metrics": metrics_a,
        "sample_b_metrics": metrics_b,
        "evidentiary_caveat": (
            "Stylometry measures writing habit, not identity. Two writers who share a genre "
            "and vocabulary can score highly without being the same person, and one writer "
            "deliberately changing their style defeats the method entirely. This is an "
            "investigative lead that requires deterministic corroboration."
        ),
    }
