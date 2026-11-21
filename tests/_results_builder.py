"""Shared helpers for the D33 result-bundle tests.

Real runs, real files and temporary roots. Nothing here touches the repository's
``data/``, ``results/``, ``uploads/`` or ``samples/``: every subprocess is given
``HATCHERY_RESULTS_ROOT`` and ``HATCHERY_SAMPLE_STORE`` inside ``tmp_path``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from engine.results import build_manifest, write_manifest

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE = (REPO_ROOT / "tests" / "fixtures" / "eicar.com").resolve()


def base_env(tmp_path: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["HATCHERY_RESULTS_ROOT"] = str(tmp_path / "results")
    env["HATCHERY_SAMPLE_STORE"] = str(tmp_path / "samples")
    env.pop("HATCHERY_SAMPLE_KEY", None)
    env.pop("HATCHERY_SAMPLE_KEY_FILE", None)
    env.pop("HATCHERY_RESULTS_RETENTION_DAYS", None)
    env.pop("HATCHERY_RESULTS_KEEP_LAST", None)
    env.pop("HATCHERY_RESULTS_WARN_RUNS", None)
    env.pop("HATCHERY_RESULTS_WARN_BYTES", None)
    return env


def run_cli(
    args: list[str],
    cwd: Path,
    *,
    env: Optional[dict[str, str]] = None,
    timeout: float = 600.0,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
        env=env,
    )


def submit(
    tmp_path: Path,
    run_id: str = "run",
    *,
    env: Optional[dict[str, str]] = None,
    sample: Path = SAMPLE,
) -> Path:
    """A real ``hatchery submit --no-sandbox`` into ``tmp_path/results/<run_id>``."""
    results = tmp_path / "results"
    results.mkdir(parents=True, exist_ok=True)
    run_dir = results / run_id
    result = run_cli(
        ["submit", str(sample), "--no-sandbox", "-o", str(run_dir)],
        tmp_path,
        env=env or base_env(tmp_path),
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
    assert (run_dir / "bundle" / "analysis.json").is_file()
    assert (run_dir / "manifest.json").is_file(), "submit must seal the run"
    return run_dir


def iso_days_ago(days: float, *, now: Optional[datetime] = None) -> str:
    moment = (now or datetime.now(timezone.utc)) - timedelta(days=days)
    return moment.isoformat()


def seal_at(run_dir: Path, sealed_at: str, *, stage: str = "submit") -> str:
    """Seal with an explicit timestamp so retention ages are deterministic."""
    manifest = build_manifest(run_dir, stage=stage, sealed_at=sealed_at)
    _path, digest = write_manifest(run_dir, manifest)
    return digest


def manifest_bytes(run_dir: Path) -> bytes:
    return (run_dir / "manifest.json").read_bytes()


def manifest_hash(run_dir: Path) -> str:
    import hashlib

    return hashlib.sha256(manifest_bytes(run_dir)).hexdigest()


def make_run(
    results_root: Path,
    run_id: str,
    *,
    sample_sha256: str = "",
    days_ago: float = 1.0,
    sealed: bool = True,
    files: Optional[dict[str, bytes]] = None,
) -> Path:
    """A minimal, sealed run: a real bundle document and a real manifest.

    Cheaper than a full analysis and enough for retention, reference and
    verification tests, which are about the run directory, not about detectors.
    """
    run_dir = results_root / run_id
    bundle = run_dir / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    analysis: dict[str, Any] = {
        "schema_version": "1.0",
        "task_id": run_id,
        "generated_at": (now - timedelta(days=days_ago + 1)).isoformat(),
        "sample": {
            "sha256": sample_sha256,
            "file_path": f"/gone/{run_id}.bin",
        },
        "static": {},
        "limitations": [],
        "errors": [],
        "summary": {"inconclusive": True},
    }
    (bundle / "analysis.json").write_text(
        json.dumps(analysis, indent=2), encoding="utf-8"
    )
    (bundle / "events.jsonl").write_text("", encoding="utf-8")
    for rel, data in (files or {}).items():
        target = run_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    if sealed:
        seal_at(run_dir, (now - timedelta(days=days_ago)).isoformat())
    return run_dir


def cli_json(
    args: list[str],
    cwd: Path,
    *,
    env: Optional[dict[str, str]] = None,
    expect: Optional[int] = None,
) -> tuple[int, dict[str, Any]]:
    result = run_cli(args, cwd, env=env)
    # Success payloads go to stdout; a refusal is a diagnostic and goes to
    # stderr (the same contract the `store` group has used since D28), so the
    # exit code is always the machine-readable signal.
    stream = result.stdout if result.stdout.strip() else result.stderr
    assert stream.strip(), f"no JSON on stdout or stderr for {args}"
    payload = json.loads(stream)
    if expect is not None:
        assert result.returncode == expect, (
            f"exit {result.returncode} != {expect}: "
            + result.stdout[-3000:]
            + result.stderr[-2000:]
        )
    return result.returncode, payload


def all_files(run_dir: Path) -> set[str]:
    return {
        path.relative_to(run_dir).as_posix()
        for path in run_dir.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
