"""Grouping: single-link clustering, and the honest edges of it."""

from __future__ import annotations

import json
from pathlib import Path

from _cluster_builder import bundle_with, fingerprint

from engine.cluster.cluster import (
    DEFAULT_THRESHOLD,
    build_clusters,
    compute_clusters,
)


def test_similar_runs_group_and_dissimilar_runs_do_not() -> None:
    a = fingerprint("a", capa=["create process", "write file"], imphash=["h"])
    b = fingerprint("b", capa=["create process", "write file"], imphash=["h"])
    c = fingerprint("c", capa=["encrypt data"], imphash=["z"])
    clusters, stats = compute_clusters([a, b, c], threshold=0.5)
    assert stats["clusters"] == 1
    assert [m.task_id for m in clusters[0].members] == ["a", "b"]
    assert stats["unclustered_runs"] == 1


def test_threshold_controls_grouping() -> None:
    a = fingerprint("a", capa=["create process", "write file", "read file"])
    b = fingerprint("b", capa=["create process", "write file", "delete file"])
    # one shared of four -> low score at a high bar, grouped at a low bar
    assert compute_clusters([a, b], threshold=0.8)[1]["clusters"] == 0
    assert compute_clusters([a, b], threshold=0.4)[1]["clusters"] == 1


def test_min_size_filters_singletons() -> None:
    a = fingerprint("a", capa=["x"])
    b = fingerprint("b", capa=["y"])
    assert compute_clusters([a, b], threshold=0.5, min_size=2)[1]["clusters"] == 0
    assert compute_clusters([a, b], threshold=0.5, min_size=1)[1]["clusters"] == 2


def test_identical_bytes_always_group_even_with_divergent_features() -> None:
    a = fingerprint("a", sha256="s" * 64, capa=["x"])
    b = fingerprint("b", sha256="s" * 64, capa=["nothing", "similar"])
    clusters, _ = compute_clusters([a, b], threshold=0.99)
    assert len(clusters) == 1
    assert clusters[0].size == 2
    assert clusters[0].identical_bytes is True
    assert clusters[0].grouped_by == "identical-sha256"


def test_similarity_clusters_are_not_labelled_identical_bytes() -> None:
    a = fingerprint("a", sha256="1" * 64, capa=["c1", "c2"])
    b = fingerprint("b", sha256="2" * 64, capa=["c1", "c2"])
    clusters, _ = compute_clusters([a, b])
    assert clusters[0].identical_bytes is False
    assert clusters[0].grouped_by == "feature-similarity"


def test_identical_content_from_two_runs_stays_two_members() -> None:
    # regression: a content-addressed id must not collapse distinct runs
    a = fingerprint("run-a", capa=["create process"])
    b = fingerprint("run-b", capa=["create process"])
    assert a.id == b.id  # same content
    clusters, stats = compute_clusters([a, b])
    assert stats["clusters"] == 1
    assert clusters[0].size == 2
    assert {m.task_id for m in clusters[0].members} == {"run-a", "run-b"}


def test_transitive_chaining_merges_and_reports_the_weakest_link() -> None:
    # a~b (identical), b~c (partial), a~c (partial) -> single-link merges all three,
    # and min_score exposes the weak link that holds the cluster together
    a = fingerprint("a", capa=["c1", "c2", "c3"])
    b = fingerprint("b", capa=["c1", "c2", "c3"])
    c = fingerprint("c", capa=["c3", "c4", "c5"])
    clusters, _ = compute_clusters([a, b, c], threshold=0.2)
    assert len(clusters) == 1
    assert clusters[0].size == 3
    assert clusters[0].min_score < clusters[0].max_score


def test_cluster_lists_shared_features_with_member_counts() -> None:
    a = fingerprint("a", capa=["create process", "write file"], imphash=["h"])
    b = fingerprint("b", capa=["create process"], imphash=["h"])
    clusters, _ = compute_clusters([a, b])
    shared = {entry["feature"]: entry["count"] for entry in clusters[0].shared}
    assert shared["capa:create process"] == 2
    assert shared["imphash:h"] == 2
    assert "capa:write file" not in shared  # only one member has it


def test_representative_is_a_member_task_id() -> None:
    a = fingerprint("a", capa=["c1"])
    b = fingerprint("b", capa=["c1"])
    c = fingerprint("c", capa=["c1"])
    clusters, _ = compute_clusters([a, b, c])
    assert clusters[0].representative in {"a", "b", "c"}


def test_cluster_id_is_stable_and_ordered() -> None:
    a = fingerprint("a", capa=["c1"])
    b = fingerprint("b", capa=["c1"])
    first, _ = compute_clusters([a, b])
    second, _ = compute_clusters([b, a])
    assert first[0].cluster_id == second[0].cluster_id


def test_default_threshold_is_sane() -> None:
    assert 0.0 < DEFAULT_THRESHOLD < 1.0


def test_build_clusters_reads_a_results_tree(tmp_path: Path) -> None:
    for name, task in (("one", "task-a"), ("two", "task-b"), ("three", "task-c")):
        run = tmp_path / name / "bundle"
        run.mkdir(parents=True)
        payload = bundle_with(task_id=task)
        payload["sample"]["sha256"] = {"one": "1", "two": "2", "three": "3"}[name] * 64
        if name == "three":
            # a genuinely different sample: different capabilities, imports, hash
            # and indicators, not just a different capability list
            payload["static"]["capa"]["capabilities"] = [{"name": "completely different"}]
            payload["static"]["pe"]["imports"] = [{"dll": "USER32.dll", "function": "MessageBoxA"}]
            payload["static"]["pe"]["exports"] = []
            payload["static"]["pe"]["suspicious_indicators"] = []
            payload["static"]["strings"] = {"urls": [], "ips": [], "domains": [],
                                            "file_paths": [], "registry_keys": [], "emails": []}
            payload["static"]["yara"] = {"matches": [{"rule": "unrelated_rule"}]}
            payload["mitre"] = {"techniques": [{"technique_id": "T1547.001"}]}
            payload["iocs"] = [{"value": "other.example"}]
        (run / "analysis.json").write_text(json.dumps(payload))

    clusters, fingerprints, stats = build_clusters(tmp_path, threshold=0.5)
    assert stats["runs_scanned"] == 3
    assert stats["clusters"] == 1
    assert {m.task_id for m in clusters[0].members} == {"task-a", "task-b"}
    assert len(fingerprints) == 3


def test_build_clusters_on_an_empty_tree(tmp_path: Path) -> None:
    clusters, fingerprints, stats = build_clusters(tmp_path)
    assert clusters == []
    assert fingerprints == []
    assert stats["runs_scanned"] == 0
