"""Root discovery for the sample store, shared by the CLI, the worker and replay.

Before D28 the sample store was ``samples/<sha256>.sample`` resolved relative to
whatever directory the process happened to run in. The API enqueued from the
checkout, a worker ran from the checkout, and a test or an operator running
``hatchery submit`` from somewhere else produced a *third* store. Replay then
looked for the sample in whichever of those the current process could see.

Every consumer now resolves the same roots the same way:

1. an explicit argument (``--store``, ``--results``);
2. the environment (``HATCHERY_SAMPLE_STORE``, ``HATCHERY_RESULTS_ROOT``);
3. the checkout that owns this package, detected by ``pyproject.toml`` beside
   the ``engine`` package — the documented editable install;
4. the working directory, so a non-editable install keeps behaving the way it
   did before.
"""

from __future__ import annotations

import os
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parents[1]  # .../engine


def repo_root() -> Path:
    """The checkout that owns this package, or the current directory."""
    candidate = PACKAGE_DIR.parent
    if (candidate / "pyproject.toml").is_file():
        return candidate
    return Path.cwd()


def _expand(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve()


def resolve_store_root(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Where encrypted, content-addressed samples live.

    The default is ``<checkout>/samples`` — the directory the old plaintext
    store used — but resolved absolutely, so a CLI run, an enqueue and a worker
    agree no matter which directory each was started from.
    """
    if explicit is not None:
        return _expand(explicit)
    configured = os.environ.get("HATCHERY_SAMPLE_STORE", "").strip()
    if configured:
        return _expand(configured)
    return _expand(repo_root() / "samples")


def resolve_results_roots(
    explicit: str | os.PathLike[str] | None = None,
) -> list[Path]:
    """Every results root a reference scan must read.

    Deliberately more than one: a reference that is missed is a sample deleted
    while a bundle still needs it. ``HATCHERY_RESULTS_ROOT`` is what the API and
    the verification script set; ``<checkout>/results`` is where the CLI writes
    by default; ``./results`` covers a run started outside the checkout. The
    list is de-duplicated and unreadable roots are simply absent.
    """
    if explicit is not None:
        return [_expand(explicit)]
    roots: list[Path] = []
    for value in (
        os.environ.get("HATCHERY_RESULTS_ROOT", "").strip(),
        os.environ.get("HATCHERY_RESULTS_DIR", "").strip(),
    ):
        if value:
            roots.append(_expand(value))
    roots.append(_expand(repo_root() / "results"))
    cwd_results = _expand(Path.cwd() / "results")
    seen: set[str] = set()
    unique: list[Path] = []
    for root in roots:
        key = str(root)
        if key in seen:
            continue
        seen.add(key)
        unique.append(root)
    if str(cwd_results) not in seen:
        unique.append(cwd_results)
    return unique


__all__ = ["PACKAGE_DIR", "repo_root", "resolve_results_roots", "resolve_store_root"]
