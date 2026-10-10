"""Similarity between two fingerprints: weighted Jaccard plus a token simhash.

Weighted Jaccard over per-category sets is the primary signal, because the
features are small, discrete sets and Jaccard is the honest measure for them.
Charikar's simhash over the whole token set is reported alongside as a
near-duplicate signal for the case where two samples differ in a few tokens but
are otherwise the same content; for small sets the weighted Jaccard dominates and
the simhash is a cross-check, not a substitute.

The result always says *what* matched, not just how much: "these two share the
same import hash and three capa capabilities" is actionable, "0.72" on its own is
not.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Optional

from engine.cluster.fingerprint import ALL_CATEGORIES, CATEGORY_WEIGHTS, Fingerprint

SIMHASH_BITS = 64


def jaccard(left: Iterable[str], right: Iterable[str]) -> Optional[float]:
    """Jaccard index of two sets, or ``None`` when both are empty (undefined)."""
    a, b = set(left), set(right)
    if not a and not b:
        return None
    union = a | b
    if not union:
        return None
    return len(a & b) / len(union)


def simhash64(tokens: Iterable[str]) -> int:
    """64-bit Charikar simhash over ``tokens``. Deterministic (blake2b)."""
    vector = [0] * SIMHASH_BITS
    unique = set(tokens)
    if not unique:
        return 0
    for token in unique:
        value = int.from_bytes(
            hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big"
        )
        for bit in range(SIMHASH_BITS):
            vector[bit] += 1 if (value >> bit) & 1 else -1
    out = 0
    for bit in range(SIMHASH_BITS):
        if vector[bit] > 0:
            out |= 1 << bit
    return out


def hamming64(left: int, right: int) -> int:
    """Number of differing bits between two 64-bit values."""
    return (left ^ right).bit_count()


def token_similarity(left: Iterable[str], right: Iterable[str]) -> float:
    """1 - normalised Hamming distance between two token simhashes."""
    return 1.0 - hamming64(simhash64(left), simhash64(right)) / SIMHASH_BITS


def _shared(left: Iterable[str], right: Iterable[str]) -> list[str]:
    return sorted(set(left) & set(right))


def compare(left: Fingerprint, right: Fingerprint) -> dict[str, Any]:
    """Compare two fingerprints. Returns a score, a breakdown and the shared tokens.

    ``score`` is the weighted mean of the per-category Jaccard values over the
    categories at least one side has tokens in. It is in ``[0, 1]``; ``0`` means
    nothing in common was recorded.
    """
    per_category: dict[str, dict[str, Any]] = {}
    weighted_sum = 0.0
    weight_total = 0.0
    shared_all: list[str] = []

    for category in ALL_CATEGORIES:
        a = set(left.features.get(category, frozenset()))
        b = set(right.features.get(category, frozenset()))
        if not a and not b:
            continue
        value = jaccard(a, b)
        if value is None:
            continue
        weight = CATEGORY_WEIGHTS[category]
        weighted_sum += weight * value
        weight_total += weight
        shared = _shared(a, b)
        shared_all.extend(f"{category}:{token}" for token in shared)
        per_category[category] = {
            "jaccard": round(value, 4),
            "shared": shared,
            "weight": weight,
        }

    score = weighted_sum / weight_total if weight_total else 0.0
    left_tokens = left.tokens()
    right_tokens = right.tokens()
    return {
        "left": left.id,
        "right": right.id,
        "score": round(score, 4),
        "token_similarity": round(token_similarity(left_tokens, right_tokens), 4),
        "hamming": hamming64(simhash64(left_tokens), simhash64(right_tokens)),
        "shared": sorted(shared_all),
        "shared_count": len(shared_all),
        "per_category": per_category,
        "same_sha256": bool(left.sha256) and left.sha256 == right.sha256,
        "same_imphash": bool(
            left.features.get("imphash")
            and left.features.get("imphash") == right.features.get("imphash")
        ),
    }


__all__ = [
    "SIMHASH_BITS",
    "compare",
    "hamming64",
    "jaccard",
    "simhash64",
    "token_similarity",
]
