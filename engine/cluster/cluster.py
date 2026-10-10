"""Group fingerprints into candidate campaigns.

Clustering is single-link (union-find) over the pairwise similarity score: two
runs are in the same cluster when their score is at least ``threshold``, and
clusters transitively close. That is the honest choice for "these might be the
same campaign" — but single-link can chain, so the result also reports the
*weakest* link in each cluster, letting an analyst see a cluster that is held
together by one marginal pair.

A cluster is never given a family name. Names are attribution, and attribution is
analyst work; the output lists the shared features that justify the grouping and
leaves the naming to a human.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from engine.cluster.fingerprint import (
    CATEGORY_WEIGHTS,
    Fingerprint,
    load_fingerprints,
)
from engine.cluster.similarity import compare

logger = logging.getLogger(__name__)

DEFAULT_THRESHOLD = 0.5
DEFAULT_MIN_SIZE = 2
# Pairwise comparison is O(n^2); refuse to silently grind on a huge results dir.
MAX_FINGERPRINTS = 500


class _UnionFind:
    def __init__(self, size: int) -> None:
        self._parent = list(range(size))

    def find(self, item: int) -> int:
        root = item
        while self._parent[root] != root:
            root = self._parent[root]
        while self._parent[item] != root:
            self._parent[item], item = root, self._parent[item]
        return root

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self._parent[right_root] = left_root


@dataclass
class Cluster:
    """A set of runs similar enough to be worth investigating together."""

    cluster_id: str
    members: list[Fingerprint] = field(default_factory=list)
    shared: list[dict[str, Any]] = field(default_factory=list)
    max_score: float = 0.0
    min_score: float = 0.0
    representative: str = ""
    identical_bytes: bool = False

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def grouped_by(self) -> str:
        """Why the members are together — identical bytes beats similarity."""
        return "identical-sha256" if self.identical_bytes else "feature-similarity"

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "representative": self.representative,
            "grouped_by": self.grouped_by,
            "identical_bytes": self.identical_bytes,
            "max_score": self.max_score,
            "min_score": self.min_score,
            "shared_features": self.shared,
            "members": [member.to_dict() for member in self.members],
        }


def _cluster_id(members: list[Fingerprint]) -> str:
    payload = ",".join(sorted(member.id for member in members))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def _shared_features(members: list[Fingerprint]) -> list[dict[str, Any]]:
    """Features present in at least two members, ranked by how many members share them."""
    counts: dict[str, dict[str, Any]] = {}
    for member in members:
        for category, values in member.features.items():
            for token in values:
                key = f"{category}:{token}"
                entry = counts.setdefault(
                    key, {"feature": key, "category": category, "count": 0}
                )
                entry["count"] += 1
    shared = [entry for entry in counts.values() if entry["count"] >= 2]
    shared.sort(
        key=lambda entry: (
            -int(entry["count"]),
            -CATEGORY_WEIGHTS.get(str(entry["category"]), 0.0),
            str(entry["feature"]),
        )
    )
    return shared


def compute_clusters(
    fingerprints: list[Fingerprint],
    *,
    threshold: float = DEFAULT_THRESHOLD,
    min_size: int = DEFAULT_MIN_SIZE,
) -> tuple[list[Cluster], dict[str, Any]]:
    """Cluster fingerprints by pairwise similarity. Returns ``(clusters, stats)``.

    Members are tracked by list index, not by content id, so two byte-identical
    samples analysed as two runs stay two members of one cluster instead of one
    silently replacing the other.
    """
    union = _UnionFind(len(fingerprints))
    # index pair (i, j) with i < j -> score
    pair_scores: dict[tuple[int, int], float] = {}
    identical_pairs: set[tuple[int, int]] = set()
    pairs_compared = 0

    for i in range(len(fingerprints)):
        for j in range(i + 1, len(fingerprints)):
            comparison = compare(fingerprints[i], fingerprints[j])
            pairs_compared += 1
            score = float(comparison["score"])
            pair_scores[(i, j)] = score
            # Identical bytes are always the same cluster regardless of feature noise.
            same_bytes = bool(comparison["same_sha256"])
            if same_bytes:
                identical_pairs.add((i, j))
            if score >= threshold or same_bytes:
                union.union(i, j)

    groups: dict[int, list[int]] = {}
    for index in range(len(fingerprints)):
        groups.setdefault(union.find(index), []).append(index)

    clusters: list[Cluster] = []
    for member_indexes in groups.values():
        if len(member_indexes) < max(1, min_size):
            continue
        member_indexes = sorted(member_indexes)
        members = [fingerprints[index] for index in member_indexes]
        scores = [
            pair_scores[(a, b)]
            for a in member_indexes
            for b in member_indexes
            if a < b and (a, b) in pair_scores
        ]
        clusters.append(
            Cluster(
                cluster_id=_cluster_id(members),
                members=members,
                shared=_shared_features(members),
                max_score=round(max(scores), 4) if scores else 1.0,
                min_score=round(min(scores), 4) if scores else 1.0,
                representative=_medoid(member_indexes, fingerprints, pair_scores),
                identical_bytes=any(
                    (a, b) in identical_pairs
                    for a in member_indexes
                    for b in member_indexes
                ),
            )
        )

    clusters.sort(key=lambda c: (-c.size, -c.max_score, c.cluster_id))
    clustered = {index for cluster in clusters for index in (m.key for m in cluster.members)}
    stats = {
        "runs_scanned": len(fingerprints),
        "clusters": len(clusters),
        "clustered_runs": len(clustered),
        "unclustered_runs": len(fingerprints) - len(clustered),
        "pairs_compared": pairs_compared,
        "threshold": threshold,
        "min_size": min_size,
    }
    return clusters, stats


def _medoid(
    member_indexes: list[int],
    fingerprints: list[Fingerprint],
    pair_scores: dict[tuple[int, int], float],
) -> str:
    """The run with the highest mean similarity to the others in its cluster."""
    if len(member_indexes) == 1:
        return fingerprints[member_indexes[0]].key

    def score(a: int, b: int) -> float:
        return pair_scores.get((min(a, b), max(a, b)), 0.0)

    best_index = member_indexes[0]
    best_mean = -1.0
    for candidate in member_indexes:
        others = [other for other in member_indexes if other != candidate]
        mean = sum(score(candidate, other) for other in others) / len(others)
        if mean > best_mean:
            best_index, best_mean = candidate, mean
    return fingerprints[best_index].key



def build_clusters(
    root: Path,
    *,
    threshold: float = DEFAULT_THRESHOLD,
    min_size: int = DEFAULT_MIN_SIZE,
    limit: Optional[int] = None,
) -> tuple[list[Cluster], list[Fingerprint], dict[str, Any]]:
    """Load every run under ``root`` and cluster them.

    Returns ``(clusters, fingerprints, stats)``. Fingerprints are returned so a
    caller can show the whole corpus, not just the grouped part.
    """
    fingerprints = load_fingerprints(root, limit=limit)
    if len(fingerprints) > MAX_FINGERPRINTS:
        logger.warning(
            "Clustering %d fingerprints is O(n^2); capping at %d",
            len(fingerprints),
            MAX_FINGERPRINTS,
        )
        fingerprints = fingerprints[:MAX_FINGERPRINTS]
    clusters, stats = compute_clusters(
        fingerprints, threshold=threshold, min_size=min_size
    )
    return clusters, fingerprints, stats


__all__ = [
    "DEFAULT_MIN_SIZE",
    "DEFAULT_THRESHOLD",
    "MAX_FINGERPRINTS",
    "Cluster",
    "build_clusters",
    "compute_clusters",
]
