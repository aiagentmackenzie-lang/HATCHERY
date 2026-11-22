"""Result bundles: integrity, retention and the growth guard (D33).

``engine/bundle.py`` remains the only writer of ``analysis.json`` and
``events.jsonl`` (D4). This package sits beside it and owns the one artifact that
describes the run directory without restating what the run found:

* :mod:`engine.results.manifest` — the single hash-manifest writer every mutating
  stage ends with, and the verifier that names the first break;
* :mod:`engine.results.retention` — the off-by-default, operator-applied
  retention policy, the rename-then-remove deletion, the prune record and the
  growth guard that warns and never deletes.

A manifest records files and provenance only. It is not signed and it is not a
second source of truth for the analysis.
"""

from __future__ import annotations

from engine.results.manifest import (
    ANALYSIS_REL,
    CLASSIFICATIONS,
    DELETING_PREFIX,
    FORMAT,
    MANIFEST_FILENAME,
    MANIFEST_VERSION,
    MAX_BYTES,
    MAX_FILES,
    ManifestError,
    STAGES,
    build_manifest,
    collect_files,
    ensure_sealed,
    hash_file,
    hatchery_version,
    is_nested_run,
    manifest_state,
    resolve_run_root,
    safe_relative_path,
    seal_corpus,
    seal_run,
    serialize,
    verify_run,
    write_manifest,
)
from engine.results.retention import (
    DEFAULT_KEEP_LAST,
    DEFAULT_WARN_BYTES,
    DEFAULT_WARN_RUNS,
    DELETING_MARKER,
    KEEP_LAST_ENV,
    PRUNE_LOG_FILENAME,
    RETENTION_DAYS_ENV,
    RESULTS_LOCK_FILENAME,
    WARN_BYTES_ENV,
    WARN_RUNS_ENV,
    ResultsLocked,
    RetentionError,
    append_prune_log,
    growth_report,
    parse_duration,
    plan_prune,
    prune_runs,
    read_prune_log,
    read_run,
    resolve_policy,
    results_lock,
    scan_root,
    status_report,
)

__all__ = [
    "ANALYSIS_REL",
    "CLASSIFICATIONS",
    "DEFAULT_KEEP_LAST",
    "DEFAULT_WARN_BYTES",
    "DEFAULT_WARN_RUNS",
    "DELETING_MARKER",
    "DELETING_PREFIX",
    "FORMAT",
    "KEEP_LAST_ENV",
    "MANIFEST_FILENAME",
    "MANIFEST_VERSION",
    "MAX_BYTES",
    "MAX_FILES",
    "ManifestError",
    "PRUNE_LOG_FILENAME",
    "RESULTS_LOCK_FILENAME",
    "RETENTION_DAYS_ENV",
    "ResultsLocked",
    "RetentionError",
    "STAGES",
    "WARN_BYTES_ENV",
    "WARN_RUNS_ENV",
    "append_prune_log",
    "build_manifest",
    "collect_files",
    "ensure_sealed",
    "growth_report",
    "hash_file",
    "hatchery_version",
    "is_nested_run",
    "manifest_state",
    "parse_duration",
    "plan_prune",
    "prune_runs",
    "read_prune_log",
    "read_run",
    "resolve_policy",
    "resolve_run_root",
    "results_lock",
    "safe_relative_path",
    "scan_root",
    "seal_corpus",
    "seal_run",
    "serialize",
    "status_report",
    "verify_run",
    "write_manifest",
]
