"""Result bundles: integrity and verification (D33).

``engine/bundle.py`` remains the only writer of ``analysis.json`` and
``events.jsonl`` (D4). This package sits beside it and owns the one artifact that
describes the run directory without restating what the run found:

* :mod:`engine.results.manifest` — the single hash-manifest writer every mutating
  stage ends with, and the verifier that names the first break.

A manifest records files and provenance only. It is not signed and it is not a
second source of truth for the analysis.
"""

from __future__ import annotations

from engine.results.manifest import (
    CLASSIFICATIONS,
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
    seal_run,
    serialize,
    verify_run,
    write_manifest,
)

__all__ = [
    "CLASSIFICATIONS",
    "FORMAT",
    "MANIFEST_FILENAME",
    "MANIFEST_VERSION",
    "MAX_BYTES",
    "MAX_FILES",
    "ManifestError",
    "STAGES",
    "build_manifest",
    "collect_files",
    "ensure_sealed",
    "hash_file",
    "hatchery_version",
    "is_nested_run",
    "manifest_state",
    "resolve_run_root",
    "safe_relative_path",
    "seal_run",
    "serialize",
    "verify_run",
    "write_manifest",
]
