"""Similarity: weighted Jaccard over categories plus a token simhash."""

from __future__ import annotations

from _cluster_builder import fingerprint

from engine.cluster.similarity import (
    SIMHASH_BITS,
    compare,
    hamming64,
    jaccard,
    simhash64,
    token_similarity,
)


def test_jaccard_basics() -> None:
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert jaccard({"a"}, {"b"}) == 0.0
    assert jaccard({"a", "b"}, {"b", "c"}) == 1 / 3
    assert jaccard(set(), set()) is None


def test_simhash_is_deterministic_and_empty_is_zero() -> None:
    assert simhash64(["a", "b"]) == simhash64(["a", "b"])
    assert simhash64([]) == 0


def test_simhash_ignores_order_and_duplicates() -> None:
    assert simhash64(["b", "a", "a"]) == simhash64(["a", "b"])


def test_hamming_and_token_similarity() -> None:
    assert hamming64(0b1010, 0b1000) == 1
    assert token_similarity(["a", "b"], ["a", "b"]) == 1.0
    assert 0.0 <= token_similarity(["a"], ["z"]) <= 1.0


def test_identical_fingerprints_score_one() -> None:
    left = fingerprint("a", capa=["create process"], imports=["k32!createfile"])
    right = fingerprint("b", capa=["create process"], imports=["k32!createfile"])
    result = compare(left, right)
    assert result["score"] == 1.0
    assert result["token_similarity"] == 1.0
    assert result["hamming"] == 0


def test_disjoint_fingerprints_score_zero() -> None:
    left = fingerprint("a", capa=["create process"])
    right = fingerprint("b", capa=["delete file"])
    assert compare(left, right)["score"] == 0.0


def test_weighting_favours_strong_evidence() -> None:
    # a shared import hash is stronger than a shared generic capability
    strong = compare(
        fingerprint("a", imphash=["deadbeef"]),
        fingerprint("b", imphash=["deadbeef"]),
    )
    weak = compare(
        fingerprint("a", capa=["create process"]),
        fingerprint("b", capa=["create process"]),
    )
    assert strong["score"] == weak["score"] == 1.0  # both full matches
    # but a partial match on the strong category scores higher than on the weak one
    strong_partial = compare(
        fingerprint("a", imphash=["x"], rule=["r1"]),
        fingerprint("b", imphash=["y"], rule=["r1"]),
    )
    weak_partial = compare(
        fingerprint("a", capa=["c1"], section=["s1"]),
        fingerprint("b", capa=["c2"], section=["s1"]),
    )
    assert strong_partial["score"] > weak_partial["score"]


def test_compare_reports_what_matched() -> None:
    left = fingerprint("a", capa=["create process", "write file"], imphash=["h"])
    right = fingerprint("b", capa=["create process"], imphash=["h"])
    result = compare(left, right)
    assert "capa:create process" in result["shared"]
    assert "imphash:h" in result["shared"]
    assert result["same_imphash"] is True
    assert result["per_category"]["capa"]["jaccard"] == 0.5


def test_compare_flags_identical_bytes() -> None:
    left = fingerprint("a", sha256="z" * 64, capa=["x"])
    right = fingerprint("b", sha256="z" * 64, capa=["y"])
    assert compare(left, right)["same_sha256"] is True


def test_simhash_bits_constant() -> None:
    assert SIMHASH_BITS == 64
