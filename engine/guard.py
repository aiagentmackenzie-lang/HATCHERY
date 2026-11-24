"""One funnel for every in-process parse of hostile bytes (D39).

Every parser HATCHERY runs — pefile, pyelftools, YARA-X, capa, the OLE/CFB and
RTF readers, ``zipfile``/``tarfile``, the strace/gVisor parsers, the PCAP
reader — consumes bytes a sample controls, **in this process**. Before this
module a parser bug escaped ``hatchery submit`` as a Python traceback: no
bundle, no manifest, no named failure, and an exit status chosen by the
interpreter. That is a denial of service *and* a broken claim at the same time,
and it is exactly the "hostile input is incomplete work, not a traceback"
lesson from the IOT-Hardware-Scanner 2.5.0 slice.

The rule enforced here has two layers.

1. **Inside a stage —** :func:`guarded` runs one parse. An unexpected
   exception becomes that stage's named failure: one line to the terminal, a
   ``<stage>: unexpected <Type>: <message>`` entry in ``bundle.errors``, and the
   traceback only in the log (for the engineer). The caller supplies a
   fallback so the bundle keeps its shape, and the run continues far enough to
   write and seal the bundle. A **documented** parser error (:data:`DOCUMENTED`
   — ``OleError``/``RtfError``) is re-raised untouched: those already have a
   caller that reports them, and flattening them would hide a real verdict.

2. **Outside every stage —** :func:`internal_error_backstop` is the last resort
   for a defect in the pipeline driver or a renderer. It prints one line and
   exits **6**, distinct from the documented 1 (INCONCLUSIVE), 2 (mismatch)
   and 2 (usage), so automation can never mistake "the tool broke" for "the
   sample was clean" or for a verdict at all. No bundle is claimed for a run
   that did not reach the bundle writer.

Neither layer hides anything: the failure is named, the exit status is non-zero
where nothing was produced, and the traceback still reaches the log.
"""

from __future__ import annotations

import functools
import logging
from typing import Any, Callable, Optional, TypeVar

import click

from engine.intake.ole import OleError
from engine.intake.rtf import RtfError

logger = logging.getLogger(__name__)

#: Parser errors that are *documented*: they name a bounded refusal and their
#: callers already turn them into a recorded reason. They must pass through a
#: guard untouched, never be flattened into a generic "unexpected" failure.
DOCUMENTED: tuple[type[BaseException], ...] = (OleError, RtfError)

#: Exit status for a defect outside every guarded stage. Documented in D39 and
#: the README's exit-status list; 1 and 2 already mean something else.
INTERNAL_ERROR_EXIT = 6

T = TypeVar("T")


def describe(stage: str, exc: BaseException) -> str:
    """The one line a failure becomes, in the log, the terminal and the bundle."""
    return f"{stage}: unexpected {type(exc).__name__}: {exc}"


def guarded(
    stage: str,
    errors: list[str],
    parse: Callable[[], T],
    *,
    fallback_factory: Optional[Callable[[], Any]] = None,
    documented: tuple[type[BaseException], ...] = DOCUMENTED,
) -> Optional[T]:
    """Run one in-process parse; an unexpected exception becomes a named failure.

    Args:
        stage: The operator-facing name of the parse ("PE analysis", "strace
            parse"). It prefixes the recorded failure, so a bundle reader can
            say which stage did not establish anything.
        errors: The bundle's error list for this run (or the stage's own). One
            entry is appended per unexpected exception.
        parse: The zero-argument call that reads hostile bytes.
        fallback_factory: Builds the empty result the caller needs so the
            bundle keeps its shape. ``None`` means "return ``None``" — correct
            for a section that is already allowed to be absent.
        documented: Documented error types that pass through untouched.

    Returns:
        ``parse()``'s value, or the fallback when it raised unexpectedly.
    """
    try:
        return parse()
    except documented:
        raise
    except Exception as exc:  # noqa: BLE001 - this is the funnel; it must catch everything
        logger.exception("%s raised an unexpected exception", stage)
        reason = describe(stage, exc)
        errors.append(reason)
        console_print(f"⚠ {reason} (recorded; the run continues)")
        if fallback_factory is None:
            return None
        return fallback_factory()


def internal_error_backstop(command: Callable[..., Any]) -> Callable[..., Any]:
    """Convert a defect outside every guarded stage into one line and exit 6.

    Applied *under* ``@cli.command(...)`` so it wraps the command body. A
    documented CLI exit (``SystemExit``), a usage error and ``KeyboardInterrupt``
    pass through untouched; every other exception is an internal error, which
    is not a verdict and must not look like one.
    """

    @functools.wraps(command)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return command(*args, **kwargs)
        except (SystemExit, click.ClickException, click.exceptions.Abort):
            raise
        except Exception as exc:  # noqa: BLE001 - the backstop is the point
            logger.exception("%s hit an internal error", command.__name__)
            console_print(
                f"internal error (exit {INTERNAL_ERROR_EXIT}): "
                f"{type(exc).__name__}: {exc}"
            )
            console_print(
                "The run did not reach a verifiable result; no bundle is claimed. "
                "The traceback is in the log."
            )
            raise SystemExit(INTERNAL_ERROR_EXIT) from exc

    return wrapper


def console_print(message: str) -> None:
    """Print through rich so the message matches the rest of the CLI.

    Imported lazily: ``engine.guard`` is imported by stage modules that must not
    pull in the CLI (and the MCP server / worker import those stages).
    """
    from rich.console import Console

    # ``markup=False``: the message contains attacker-influenced text (an
    # exception's ``str``), and rich would otherwise treat ``[...]`` in it as
    # markup and silently drop or misinterpret it.
    Console().print(message, style="red", markup=False, highlight=False)
