"""Local campaign clustering across runs — similarity and shared lineage.

One analysis answers "what does this sample do?". A pile of analyses answers a
better question: "which of these are the same campaign?". This package derives a
**fingerprint** from each run's bundle and groups fingerprints that are similar
enough to be worth an analyst's attention.

Two properties are deliberate:

* **Derived, never a second producer.** A fingerprint is computed from the bundle
  on demand. Nothing new is written into the bundle, so there is no second path
  that can disagree with it (D4).
* **Similarity is not attribution.** Shared features are common in benign
  software too (the same compiler stub, the same library, the same packing
  toolkit). A cluster is a lead to investigate, not a family name, and this
  package never names a family — guessing one is the thing D15 forbids for
  techniques, applied to malware families.
"""

from __future__ import annotations

from engine.cluster.cluster import Cluster, build_clusters, compute_clusters
from engine.cluster.fingerprint import (
    CATEGORY_WEIGHTS,
    Fingerprint,
    fingerprint_from_bundle,
    fingerprint_from_run,
    load_fingerprints,
)
from engine.cluster.similarity import compare, hamming64, jaccard, simhash64

__all__ = [
    "CATEGORY_WEIGHTS",
    "Cluster",
    "Fingerprint",
    "build_clusters",
    "compare",
    "compute_clusters",
    "fingerprint_from_bundle",
    "fingerprint_from_run",
    "hamming64",
    "jaccard",
    "load_fingerprints",
    "simhash64",
]
