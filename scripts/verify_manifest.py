#!/usr/bin/env python3
"""Verify a HATCHERY run directory with Python and nothing else (D34).

This is the verifier an operator sends *with* the run. It uses only the standard
library and ``engine.results.manifest`` — no click, no rich, no YARA-X, no capa,
no Docker, no database and no ``HATCHERY_*`` environment. It deliberately does
not re-implement any rule: it calls the same :func:`verify_run` that
``hatchery results verify`` calls, so the two cannot drift into two answers.

Usage::

    python verify_manifest.py RUN [--expect-manifest SHA256] [--json]

``RUN`` is the run directory (or its ``bundle/``). The classification, state and
exit codes are the same as ``hatchery results verify``:

* 0 — ``intact`` (every file and every nested unit verified) or ``unsealed``
  (a legacy run with no manifest at all — never ``ok``);
* 1 — ``broken``, with a classification and the path of the first break;
* 2 — a usage error (the path does not exist, or is not a directory).

A run directory's conclusion includes its nested units: a nested replay with no
manifest is ``nested-unsealed`` and exits 1, because the directory ships evidence
that cannot be verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _checkout_root() -> Path:
    """The repository root that holds ``engine/`` — the script lives in scripts/."""
    return Path(__file__).resolve().parent.parent


def _load_verifier():
    root = _checkout_root()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from engine.results.manifest import (  # noqa: PLC0415 - after sys.path setup
        ManifestError,
        resolve_run_root,
        verify_run,
    )

    return ManifestError, resolve_run_root, verify_run


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify_manifest.py",
        description=(
            "Verify a HATCHERY run directory using the standard library and the "
            "same verifier as `hatchery results verify`."
        ),
    )
    parser.add_argument("run", help="run directory (or its bundle/) to verify")
    parser.add_argument(
        "--expect-manifest",
        dest="expect_manifest",
        default=None,
        metavar="SHA256",
        help="the manifest sha256 recorded when the run was delivered (the anchor)",
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true", help="one JSON object on stdout"
    )
    return parser


def _human(report: dict) -> str:
    lines = [
        "HATCHERY result bundle",
        f"Run:    {report['run_dir']}",
        f"State:  {report['state']}",
    ]
    if report.get("classification"):
        lines.append(f"Break:  {report['classification']} at {report['path']}")
    if report.get("manifest_sha256"):
        lines.append(f"Manifest: {report['manifest_sha256']}")
    if report.get("anchor"):
        match = "matches the anchor" if report["anchor"]["match"] else "does NOT match the anchor"
        lines.append(f"Anchor: {match} ({report['anchor']['actual']})")
    if report.get("stage") or report.get("sealed_at"):
        lines.append(f"Stage:  {report.get('stage') or '(none)'} · sealed {report.get('sealed_at') or '(never)'}")
    if report["state"] != "unsealed":
        lines.append(
            f"Files:  {report['file_count']} ({report['hashed']} hashed) · "
            f"{report['total_bytes']} bytes · manifest v{report['manifest_version']}"
        )
    for nested in report.get("nested_runs") or []:
        if nested["state"] == "unsealed":
            lines.append(
                f"  nested replay {nested['run_id']}: unsealed — no manifest; this "
                "directory ships evidence that cannot be verified"
            )
        else:
            detail = (
                f" ({nested['classification']} at {nested['path']})"
                if nested.get("classification")
                else ""
            )
            lines.append(f"  nested replay {nested['run_id']}: {nested['state']}{detail}")
    if report.get("anchor") and report["anchor"].get("match") and report["state"] == "broken":
        lines.append(
            "The anchor matches, so this is the parent manifest you recorded — but "
            "the directory is still broken. The anchor proves the parent manifest, "
            "not that every nested unit inside this directory is verifiable."
        )
    if report.get("error"):
        lines.append(str(report["error"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        ManifestError, resolve_run_root, verify_run = _load_verifier()
    except ImportError as exc:  # pragma: no cover - a broken checkout
        print(f"verify_manifest: cannot import the HATCHERY verifier: {exc}", file=sys.stderr)
        return 2

    try:
        run_root = resolve_run_root(args.run)
    except ManifestError as exc:
        if args.as_json:
            print(
                json.dumps(
                    {"ok": False, "reason": exc.reason, "message": exc.message},
                    indent=2,
                ),
                file=sys.stderr,
            )
        else:
            print(f"verify_manifest: {exc.reason}: {exc.message}", file=sys.stderr)
        return 2

    report = verify_run(run_root, expect_manifest=args.expect_manifest)
    # The same key the CLI adds, so a consumer can read either output unchanged.
    report["run"] = str(args.run)

    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(_human(report))

    if report["state"] in ("intact", "unsealed"):
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
