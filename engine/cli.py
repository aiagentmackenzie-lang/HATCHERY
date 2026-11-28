"""HATCHERY CLI — command-line interface for the malware sandbox engine.

Usage:
    hatchery submit <file>        Submit a sample for full analysis
    hatchery status <task_id>     Check analysis status
    hatchery report <task_id>     Generate analysis report
    hatchery iocs <task_id>       Extract IOCs
    hatchery static <file>        Run static analysis only
    hatchery build                Build the sandbox Docker image
"""

from __future__ import annotations

import dataclasses
import functools
import json
import logging
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Any, NoReturn, Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from engine.bundle import (
    AnalysisBundle,
    compute_limitations,
    normalize_events,
    render_limitations,
    write_bundle,
)
from engine.export.ocsf_export import OCSF_SCHEMA_VERSION
from engine.guard import guarded, internal_error_backstop
from engine.static.yara_scanner import lint_rules

console = Console()

# Global analysis tasks (in-memory; production would use a database)
_tasks: dict[str, dict] = {}


def _setup_logging(verbose: bool) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(
            console=console,
            show_time=True,
            show_path=False,
        )],
    )


def _print_hashes(hashes: dict) -> None:
    """Pretty-print hash results."""
    table = Table(title="File Hashes", show_header=True)
    table.add_column("Algorithm", style="cyan")
    table.add_column("Hash", style="green")

    table.add_row("MD5", hashes.get("md5", "N/A"))
    table.add_row("SHA1", hashes.get("sha1", "N/A"))
    table.add_row("SHA256", hashes.get("sha256", "N/A"))
    if hashes.get("ssdeep"):
        table.add_row("SSDeep", hashes["ssdeep"])
    table.add_row("Size", f"{hashes.get('file_size', 0)} bytes")

    console.print(table)


def _print_yara_results(yara_result: dict) -> None:
    """Pretty-print YARA scan results."""
    matches = yara_result.get("matches", [])
    if not matches:
        console.print("[dim]No YARA matches[/dim]")
        return

    table = Table(title="YARA Matches", show_header=True)
    table.add_column("Rule", style="red")
    table.add_column("Namespace", style="cyan")
    table.add_column("Description", style="yellow")
    table.add_column("Tags", style="magenta")

    for match in matches:
        meta = match.get("meta", {})
        table.add_row(
            match.get("rule", "unknown"),
            match.get("namespace", ""),
            meta.get("description", ""),
            ", ".join(match.get("tags", [])),
        )

    console.print(table)


def _print_capa_results(capa_result: dict) -> None:
    """Pretty-print capa results."""
    capabilities = capa_result.get("capabilities", [])
    if not capabilities:
        console.print("[dim]No capa capabilities detected[/dim]")
        return

    table = Table(title="Capabilities (capa)", show_header=True)
    table.add_column("Capability", style="red")
    table.add_column("Namespace", style="cyan")
    table.add_column("ATT&CK", style="yellow")

    for cap in capabilities:
        attack_strs = []
        for attack in cap.get("attack_techniques", []):
            attack_strs.append(f"{attack.get('id', '')} {attack.get('technique', '')}")
        table.add_row(
            cap.get("name", "unknown"),
            cap.get("namespace", ""),
            ", ".join(attack_strs) if attack_strs else "-",
        )

    console.print(table)


def _print_packer_results(packer_result: dict) -> None:
    """Pretty-print packer detection results."""
    packers = packer_result.get("packers", [])
    if not packers:
        console.print("[dim]No packers detected[/dim]")
        return

    table = Table(title="Packer Detection", show_header=True)
    table.add_column("Packer", style="red")
    table.add_column("Confidence", style="yellow")
    table.add_column("Indicators", style="cyan")

    for p in packers:
        table.add_row(
            p.get("name", "unknown"),
            p.get("confidence", "unknown"),
            ", ".join(p.get("indicators", [])),
        )

    console.print(table)


def _print_iocs(ioc_report: dict) -> None:
    """Pretty-print IOC extraction results."""
    summary = ioc_report.get("summary", {})
    if not summary:
        console.print("[dim]No IOCs extracted[/dim]")
        return

    table = Table(title="IOCs Summary", show_header=True)
    table.add_column("Type", style="cyan")
    table.add_column("Count", style="red")

    for ioc_type, count in sorted(summary.items()):
        table.add_row(ioc_type, str(count))

    console.print(table)

    # Print high/critical IOCs
    high_iocs = [
        i for i in ioc_report.get("iocs", [])
        if i.get("severity") in ("high", "critical")
    ]
    if high_iocs:
        console.print("\n[red]⚠ High/Critical IOCs:[/red]")
        for ioc in high_iocs:
            console.print(
                f"  [{ioc.get('severity', '').upper()}] "
                f"{ioc.get('type', '')}: {ioc.get('value', '')} "
                f"({ioc.get('context', '')})"
            )


def _print_delivery(result: Any) -> None:
    """Print what a delivery container yielded, and what it refused."""
    detail = f" — {result.classification.detail}" if result.classification.detail else ""
    console.print(f"  Delivery format: [cyan]{result.format.value}{detail}[/cyan]")
    if result.flags:
        console.print(f"  Flags: [yellow]{', '.join(result.flags)}[/yellow]")

    children = result.children
    if children:
        table = Table(title="Extracted from delivery container", show_header=True)
        table.add_column("File", style="green")
        table.add_column("Size", style="cyan")
        table.add_column("Format", style="magenta")
        table.add_column("Flags", style="yellow")
        for child in children[:20]:
            table.add_row(
                child.name, f"{child.size:,}", child.format,
                ", ".join(child.flags) or "-",
            )
        console.print(table)
        if len(children) > 20:
            console.print(f"  [dim]... {len(children) - 20} more[/dim]")

    for item in result.unsupported:
        console.print(
            f"  [yellow]not extracted:[/yellow] {item.get('path', '')} "
            f"({item.get('format', '')}) — {item.get('reason', '')}"
        )
    for problem in result.errors:
        console.print(f"  [red]delivery error: {problem}[/red]")

    details = result.details or {}
    link = details.get("link") or {}
    if link.get("target") or link.get("arguments"):
        target = link.get("target") or link.get("target_idlist") or ""
        console.print(f"  LNK target: [cyan]{target}[/cyan]")
        if link.get("arguments"):
            console.print(f"  LNK arguments: [yellow]{link['arguments']}[/yellow]")
    iso = details.get("iso") or {}
    if iso:
        flavor = " (Joliet)" if iso.get("joliet") else ""
        console.print(f"  ISO volume: [cyan]{iso.get('volume_identifier', '')}[/cyan]{flavor}")
    ole_details = details.get("ole") or {}
    embedded_packages = [
        name
        for info in ole_details.values()
        for name in (info.get("embedded") or [])
    ]
    if embedded_packages:
        console.print(
            f"  OLE embedded packages: [cyan]{', '.join(embedded_packages)}[/cyan]"
        )
    rtf_details = details.get("rtf") or {}
    rtf_count = int(rtf_details.get("objects") or 0)
    if rtf_count:
        classes = rtf_details.get("objclasses") or []
        suffix = f" ({', '.join(classes)})" if classes else ""
        console.print(f"  RTF embedded objects: [cyan]{rtf_count}[/cyan]{suffix}")


def _inotify_line_count(path: Path) -> int:
    return len(path.read_text(errors="replace").splitlines())


def _inotify_events(path: Path) -> dict:
    from engine.bundle import events_from_inotify

    return {"events": events_from_inotify(path)}


def _child_static(
    hasher: Any,
    string_extractor: Any,
    yara_scanner: Any,
    packer_detector: Any,
    child: Any,
) -> dict:
    return {
        "hashes": hasher.hash_file(child.path).to_dict(),
        "strings": string_extractor.extract(child.path).to_dict(),
        "yara": yara_scanner.scan(child.path).to_dict(),
        "packer": packer_detector.detect(child.path).to_dict(),
    }


def _parse_syscall_log(
    sandbox_result: Any, stage_errors: list[str]
) -> tuple[Any, Any]:
    """Parse the syscall source this tier's collector produced (D39).

    Tier 2 uses gVisor's Sentry trace; tier 1 uses in-guest strace. Both are
    parsed in-process from a file the guest wrote, so both go through the same
    funnel: a parser bug names the stage and leaves ``syscall_result`` as
    ``None`` (the evasion and ATT&CK stages then simply do not run) instead of
    throwing away the sandbox result that *did* succeed.

    Returns ``(syscall_result, gvisor_result)``.
    """
    gvisor_result: Any = None
    syscall_result: Any = None
    if sandbox_result.gvisor_trace_log:
        from engine.monitor.gvisor_strace import GvisorStraceParser

        console.print("\n  [bold]Parsing gVisor Sentry trace...[/bold]")
        gvisor_path = Path(sandbox_result.gvisor_trace_log)
        if gvisor_path.exists():
            gvisor_result = guarded(
                "gVisor Sentry trace parse",
                stage_errors,
                functools.partial(GvisorStraceParser().parse_file, gvisor_path),
            )
            syscall_result = gvisor_result
            if gvisor_result is not None:
                console.print(
                    f"  Events parsed: [cyan]{gvisor_result.parsed_events}[/cyan] "
                    f"(source: gvisor-sentry)"
                )
    elif sandbox_result.strace_log:
        from engine.monitor.strace_parser import StraceParser

        console.print("\n  [bold]Parsing syscall log...[/bold]")
        strace_path = Path(sandbox_result.strace_log)
        if strace_path.exists():
            syscall_result = guarded(
                "strace parse",
                stage_errors,
                functools.partial(StraceParser().parse_file, strace_path),
            )
            if syscall_result is not None:
                console.print(
                    f"  Events parsed: [cyan]{syscall_result.parsed_events}[/cyan]"
                )
    elif sandbox_result.gvisor_trace_error:
        console.print(
            f"  [yellow]gVisor Sentry trace unavailable: "
            f"{sandbox_result.gvisor_trace_error}[/yellow]"
        )
    return syscall_result, gvisor_result


def _run_delivery_intake(file: Path, results_dir: Path) -> tuple[Any, dict]:
    """Open a delivery container and statically analyse everything inside.

    The single intake path (``extract_delivery``) is called exactly here. Every
    extracted child is hashed and run through the cheap static stages (YARA,
    strings, packer detection) so its own IOCs reach the IOC extractor. The
    children are **not** detonated, and the run says so in its limitations.
    """
    from engine.intake.delivery import (
        DeliveryClassification,
        DeliveryFormat,
        DeliveryIntakeResult,
        extract_delivery,
    )
    from engine.intake.hasher import MultiHasher
    from engine.intake.strings import StringExtractor
    from engine.static.yara_scanner import YARAScanner
    from engine.static.packer_detect import PackerDetector

    # D39: a defect in classification or extractor dispatch is this stage's
    # named failure, not a traceback. ``extract_delivery`` already catches per
    # container; this covers the module-level work around it (output root,
    # mkdir) and keeps the funnel in one place.
    errors: list[str] = []
    result = guarded(
        "delivery intake",
        errors,
        lambda: extract_delivery(file, results_dir / "delivery"),
        fallback_factory=lambda: DeliveryIntakeResult(
            classification=DeliveryClassification(DeliveryFormat.UNKNOWN)
        ),
    )
    assert result is not None, "the fallback above is never None"
    result.errors.extend(errors)

    hasher = MultiHasher()
    string_extractor = StringExtractor()
    yara_scanner = YARAScanner()
    packer_detector = PackerDetector()
    for child in result.children:
        child_errors: list[str] = []
        child.static = guarded(
            f"{child.name}: static analysis",
            child_errors,
            functools.partial(
                _child_static,
                hasher,
                string_extractor,
                yara_scanner,
                packer_detector,
                child,
            ),
            fallback_factory=dict,
        ) or {}
        result.errors.extend(child_errors)

    return result, result.to_dict()


def _enqueue_refusal(
    reason: str, message: str, *, limit: Optional[int] = None
) -> NoReturn:
    """Refuse a queued submission in the one shape a caller can parse (D42).

    ``submit --enqueue`` prints exactly one JSON object on stdout, and the API
    reads it. A refusal used to be a human line of coloured text, so a server
    could only quote it back and guess at a status code. It is now
    ``{"ok": false, "reason": ...}`` on stdout with exit 1: stdout stays
    machine-readable, stderr stays for humans, and ``reason`` is the store's own
    vocabulary rather than a sentence a caller has to pattern-match.
    """
    payload: dict[str, Any] = {"ok": False, "reason": reason, "message": message}
    if limit is not None:
        payload["limit"] = limit
    print(json.dumps(payload))
    raise SystemExit(1)


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug logging")
def cli(verbose: bool) -> None:
    """HATCHERY — Docker-based malware sandbox engine.

    Watch it hatch. Watch it burn.
    """
    _setup_logging(verbose)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path), required=False)
@click.option("--from-store", "from_store", default=None, help="Analyse a stored sample by its sha256 address (internal: worker/replay)")
@click.option("--sample-hint", "sample_hint", default=None, help="Original path to record for a stored sample (informational)")
@click.option("--timeout", default=120, help="Sandbox timeout in seconds")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output directory")
@click.option("--no-sandbox", is_flag=True, help="Skip sandbox execution (static only)")
@click.option("--emulate", is_flag=True, help="Run Windows PE emulation (needs the emulation image)")
@click.option("--emulate-timeout", default=60, help="Emulated-run timeout in seconds")
@click.option("--emulate-raw", is_flag=True, help="Treat the sample as raw shellcode")
@click.option("--no-emulate-capa", is_flag=True, help="Skip capa over memory snapshots")
@click.option("--allow-host-emulation", is_flag=True, help="Escape hatch: emulate on the bare host (loudly unsupported)")
@click.option("--triage", "triage_enabled", is_flag=True, default=False, envvar="HATCHERY_TRIAGE", help="Run local LLM triage over the bundle (needs Ollama)")
@click.option("--triage-model", default=None, help="Ollama model for triage (else auto-pick a local model)")
@click.option("--allow-remote-model", is_flag=True, help="Escape hatch: allow a remote endpoint or a `:cloud` model to see sample text")
@click.option("--enqueue", is_flag=True, help="Queue the job for a worker instead of analysing now")
@click.option("--queue", "queue_db", type=click.Path(path_type=Path), default=None, help="Queue database (default: data/queue.db or HATCHERY_QUEUE_DB)")
@click.option("--job-id", default=None, help="Job id to enqueue under (default: a fresh id)")
@click.option("--requeue", is_flag=True, help="Re-queue an existing terminal job instead of refusing")
@click.option("--name", "sample_name", default=None, help="Filename to record for a sample that has no path (a stored sample)")
@internal_error_backstop
def submit(
    file: Optional[Path],
    from_store: Optional[str],
    sample_hint: Optional[str],
    timeout: int,
    output: Optional[Path],
    no_sandbox: bool,
    emulate: bool,
    emulate_timeout: int,
    emulate_raw: bool,
    no_emulate_capa: bool,
    allow_host_emulation: bool,
    triage_enabled: bool,
    triage_model: Optional[str],
    allow_remote_model: bool,
    enqueue: bool,
    queue_db: Optional[Path],
    job_id: Optional[str],
    requeue: bool,
    sample_name: Optional[str],
) -> None:
    """Submit a sample for full analysis.

    Runs static analysis (hashes, strings, YARA, capa, packer detection),
    optionally detonates Linux ELF in the sandbox container, and optionally
    emulates a Windows PE with Speakeasy. Emulation is a declared, containerized
    stage — not an isolation boundary.

    With ``--enqueue`` the job is written to the durable queue instead and a
    worker (``hatchery worker``) runs it later. In that mode the command prints
    one JSON object on stdout and does not analyse anything. The accepted bytes
    are encrypted into the sample store before the job row is written, so the
    job survives deletion of the original path.

    ``--from-store`` analyses a stored sample by its content address instead of a
    file. It is how a worker executes a queued job and how replay re-analyses a
    record whose original path is gone; the plaintext is decrypted in memory and
    handed to the path-based pipeline through a single-use staging file that is
    removed when the run ends.

    With ``--enqueue`` as well, ``--from-store`` queues an **already stored**
    sample (D42): nothing is read, decrypted or copied, and the job records the
    content address instead of a path. That is the second half of the HTTP
    boundary — `hatchery store put --stdin` takes the bytes, this queues the
    address it returned (see ``store put``).
    """
    from engine.intake.uploader import SampleUploader
    from engine.store import SampleStore, SampleStoreError
    from engine.store.staging import StagedPlaintext

    if from_store and file is not None:
        raise click.UsageError("--from-store takes a content address, not a FILE")
    if not from_store and file is None:
        raise click.UsageError("submit needs a sample FILE or --from-store SHA256")

    job_args = {
        "timeout": timeout,
        "no_sandbox": no_sandbox,
        "emulate": emulate,
        "emulate_timeout": emulate_timeout,
        "emulate_raw": emulate_raw,
        "no_emulate_capa": no_emulate_capa,
        "allow_host_emulation": allow_host_emulation,
        "triage": triage_enabled,
        "triage_model": triage_model,
        "allow_remote_model": allow_remote_model,
    }
    if enqueue:
        # Queue, do not analyse. stdout is a single JSON object so a server can
        # read the job id without parsing human-facing output.
        from engine.queue import JobError, JobStore, resolve_queue_db

        # D28: the accepted bytes enter the encrypted store *before* the job row
        # exists. A queued job can therefore be executed after the original path
        # is deleted, and the job records the content address it will run.
        # D34: construction can lose a race with another opener; that is a named
        # store-busy failure and exit 1, never a traceback.
        source_path: Optional[Path] = None
        if from_store:
            # D42: queue an address that is already stored. Nothing is read or
            # decrypted here — the blob's existence is checked cheaply and the
            # worker authenticates it before the run (D28), so a lying index
            # fails there rather than being trusted here.
            try:
                sample_store = SampleStore()
            except SampleStoreError as exc:
                _enqueue_refusal(exc.reason, exc.message)
            try:
                if not sample_store.has(from_store):
                    _enqueue_refusal(
                        "not-found",
                        f"no stored sample {from_store}; store the bytes first "
                        "(`hatchery store put`)",
                    )
            finally:
                sample_store.close()
            sample_sha256 = from_store
        else:
            try:
                sample_store = SampleStore()
            except SampleStoreError as exc:
                _enqueue_refusal(exc.reason, exc.message)
            try:
                assert file is not None
                record = sample_store.put_file(file)
                source_path = file
                sample_sha256 = record.sha256
            except SampleStoreError as exc:
                _enqueue_refusal(
                    exc.reason,
                    exc.message,
                    limit=sample_store.max_bytes
                    if exc.reason == "too-large"
                    else None,
                )
            finally:
                sample_store.close()
            if sample_store.generated_key_notice:
                click.echo(
                    f"WARNING: {sample_store.generated_key_notice}", err=True
                )

        if sample_name:
            recorded_name = Path(sample_name).name
        elif source_path is not None:
            recorded_name = source_path.name
        else:
            recorded_name = f"{sample_sha256[:12]}.sample"

        store = JobStore(resolve_queue_db(queue_db))
        try:
            job = store.enqueue(
                source_path,
                output_dir=output,
                args=job_args,
                sample_sha256=sample_sha256,
                sample_store_ref=sample_sha256,
                sample_name=recorded_name,
                job_id=job_id,
                requeue=requeue,
            )
        except JobError as exc:
            console.print(f"[red]{exc}[/red]")
            raise SystemExit(1)
        finally:
            store.close()
        print(json.dumps({
            "ok": True,
            "job_id": job.job_id,
            "status": job.status,
            "sample_path": job.sample_path,
            "sample_name": job.sample_name,
            "sample_sha256": job.sample_sha256,
            "sample_store_ref": job.sample_store_ref,
            "output_dir": job.output_dir,
            "queue_db": str(resolve_queue_db(queue_db)),
        }))
        return

    try:
        sample_store = SampleStore()
    except SampleStoreError as exc:
        console.print(f"[red]Cannot store the sample: {exc.reason}: {exc.message}[/red]")
        raise SystemExit(1) from exc
    staged: Optional[StagedPlaintext] = None
    if from_store:
        try:
            stored = sample_store.read(from_store)
        except SampleStoreError as exc:
            console.print(
                f"[red]Cannot read stored sample {from_store}: {exc.reason}: {exc.message}[/red]"
            )
            raise SystemExit(1)
        sample_name = Path(sample_hint).name if sample_hint else f"{stored.sha256[:12]}.sample"
        staged = StagedPlaintext(stored.data, sample_name)
        file = staged.path
        recorded_path = str(Path(sample_hint)) if sample_hint else f"store:{stored.sha256}"
        store_record = {
            "reference": stored.sha256,
            "encryption": stored.encryption,
            "blob": sample_store.blob_path(stored.sha256).name,
        }
        uploader = SampleUploader(store=sample_store)
        metadata = uploader.describe(
            sample_name,
            stored.data,
            storage_path=sample_store.blob_path(stored.sha256),
            sha256=stored.sha256,
            encryption=stored.encryption,
        )
    else:
        assert file is not None
        sample_name = file.name
        recorded_path = str(file)
        uploader = SampleUploader(store=sample_store)
        try:
            metadata = uploader.upload(file)
        except SampleStoreError as exc:
            console.print(f"[red]Cannot store the sample: {exc.reason}: {exc.message}[/red]")
            raise SystemExit(1)
        store_record = metadata.store_reference()
        file = Path(file)

    task_id = uuid.uuid4().hex[:12]
    console.print(Panel(
        f"[bold orange_red1]HATCHERY[/bold orange_red1] — Submitting sample for analysis\n"
        f"Task ID: [cyan]{task_id}[/cyan]\n"
        f"File: [green]{sample_name}[/green]",
        title="🔴 New Analysis",
    ))

    results_dir = output or Path(f"results/{task_id}")
    results_dir.mkdir(parents=True, exist_ok=True)

    # D39: every in-process parse below reads bytes the sample controls. The
    # guard turns an unexpected parser exception into that stage's named
    # failure in ``bundle.errors`` and keeps the run alive; the bundle is still
    # written and sealed. Documented parser errors are not flattened.
    stage_errors: list[str] = []

    # Initialize all analysis modules
    from engine.intake.uploader import SampleUploader
    from engine.intake.hasher import MultiHasher
    from engine.intake.strings import StringClassification, StringExtractor
    from engine.intake.pe_analyzer import PEAnalyzer
    from engine.intake.elf_analyzer import ELFAnalyzer
    from engine.intake.delivery import DeliveryFormat
    from engine.static.yara_scanner import YARAResult, YARAScanner
    from engine.static.capa_scanner import CapaResult, CapaScanner
    from engine.static.packer_detect import PackerResult, PackerDetector
    from engine.ioc.extractor import IOCExtractor, IOCReport
    from engine.export.report import ReportGenerator
    from engine.export.stix import STIXExporter
    from engine.export.mitre_map import MITREMapper

    task_data: dict = {
        "task_id": task_id,
        "file": str(file),
        "status": "running",
        "start_time": time.time(),
    }

    # Phase 1: Sample intake
    console.print("\n[bold]▸ Phase 1: Sample Intake[/bold]")

    # Delivery-format intake runs before static analysis: a ZIP, Office
    # document, archive or HTML/SVG page is opened once, and its children join
    # the same static pipeline. A container that is detected but not unpacked
    # is reported in the terminal, the bundle, the report and the limitations
    # — never silently treated as an empty file (D19).
    delivery_result, delivery_dict = _run_delivery_intake(file, results_dir)
    if delivery_result.format is not DeliveryFormat.UNKNOWN:
        metadata.file_type = delivery_result.format.value.upper()

    console.print(f"  File type: [cyan]{metadata.file_type}[/cyan]")
    console.print(f"  Size: [cyan]{metadata.file_size:,} bytes[/cyan]")
    if delivery_result.format is not DeliveryFormat.UNKNOWN:
        _print_delivery(delivery_result)

    # Hash computation
    hasher = MultiHasher()
    hash_result = hasher.hash_file(file)
    _print_hashes(hash_result.to_dict())

    # String extraction
    console.print("\n[bold]▸ String Extraction[/bold]")
    string_extractor = StringExtractor()
    strings = guarded(
        "string extraction",
        stage_errors,
        lambda: string_extractor.extract(file),
        fallback_factory=StringClassification,
    )
    assert strings is not None, "the fallback above is never None"
    console.print(f"  URLs: [red]{len(strings.urls)}[/red]")
    console.print(f"  IPs: [red]{len(strings.ips)}[/red]")
    console.print(f"  Domains: [red]{len(strings.domains)}[/red]")
    console.print(f"  Emails: [red]{len(strings.emails)}[/red]")
    console.print(f"  Registry keys: [red]{len(strings.registry_keys)}[/red]")
    console.print(f"  Total strings: [dim]{len(strings.all_strings)}[/dim]")

    # PE/ELF analysis. The result objects are kept: the bundle is the source of
    # truth (D4) and its ``static.pe``/``static.elf`` sections are what the API's
    # pe_json/elf_json columns, the report and the cluster fingerprint read (D38).
    # They were previously printed and thrown away, so the readers always found
    # nothing. ``None`` in the bundle means "not applicable", never "we dropped it".
    pe_result: Any = None
    elf_result: Any = None
    if metadata.file_type == "PE":
        console.print("\n[bold]▸ PE Analysis[/bold]")
        pe_analyzer = PEAnalyzer()
        pe_result = guarded(
            "PE analysis", stage_errors, lambda: pe_analyzer.analyze(file)
        )
        if pe_result is not None and pe_result.is_valid_pe:
            console.print(f"  Machine: [cyan]{pe_result.machine_type}[/cyan]")
            console.print(f"  Subsystem: [cyan]{pe_result.subsystem}[/cyan]")
            console.print(f"  Sections: [cyan]{len(pe_result.sections)}[/cyan]")
            console.print(f"  Imports: [cyan]{len(pe_result.imports)}[/cyan]")
            console.print(f"  Compile time: [cyan]{pe_result.compile_timestamp}[/cyan]")
            if pe_result.suspicious_indicators:
                console.print(f"  [red]⚠ Suspicious indicators: {len(pe_result.suspicious_indicators)}[/red]")
                for ind in pe_result.suspicious_indicators[:5]:
                    console.print(f"    • {ind}")

    elif metadata.file_type == "ELF":
        console.print("\n[bold]▸ ELF Analysis[/bold]")
        elf_analyzer = ELFAnalyzer()
        elf_result = guarded(
            "ELF analysis", stage_errors, lambda: elf_analyzer.analyze(file)
        )
        if elf_result is not None and elf_result.is_valid_elf:
            console.print(f"  Architecture: [cyan]{elf_result.arch}[/cyan]")
            console.print(f"  Type: [cyan]{elf_result.elf_type}[/cyan]")
            console.print(f"  Sections: [cyan]{len(elf_result.sections)}[/cyan]")
            console.print(f"  Security: NX={elf_result.security.has_nx}, PIE={elf_result.security.is_pie}")

    # Phase 1: Static analysis
    console.print("\n[bold]▸ Static Analysis[/bold]")

    # YARA scanning
    console.print("\n  [bold]YARA Scanning...[/bold]")
    yara_scanner = YARAScanner()
    yara_result = guarded(
        "YARA scan",
        stage_errors,
        lambda: yara_scanner.scan(file),
        fallback_factory=lambda: YARAResult(
            rules_loaded=0, error="scan failed unexpectedly; see bundle errors"
        ),
    )
    assert yara_result is not None, "the fallback above is never None"
    console.print(f"  Rules loaded: [cyan]{yara_result.rules_loaded}[/cyan]")
    console.print(f"  Matches: [red]{len(yara_result.matches)}[/red]")
    _print_yara_results(yara_result.to_dict())

    # capa analysis
    console.print("\n  [bold]capa Analysis...[/bold]")
    capa_scanner = CapaScanner()
    capa_result = guarded(
        "capa analysis",
        stage_errors,
        lambda: capa_scanner.scan(file),
        fallback_factory=lambda: CapaResult(
            error="analysis failed unexpectedly; see bundle errors"
        ),
    )
    assert capa_result is not None, "the fallback above is never None"
    console.print(f"  Available: [cyan]{capa_result.is_available}[/cyan]")
    if capa_result.is_available:
        console.print(f"  Capabilities: [red]{len(capa_result.capabilities)}[/red]")
        _print_capa_results(capa_result.to_dict())

    # Packer detection
    console.print("\n  [bold]Packer Detection...[/bold]")
    packer_detector = PackerDetector()
    packer_result = guarded(
        "packer detection",
        stage_errors,
        lambda: packer_detector.detect(file),
        fallback_factory=lambda: PackerResult(
            error="detection failed unexpectedly; see bundle errors"
        ),
    )
    assert packer_result is not None, "the fallback above is never None"
    console.print(f"  Packed: [red]{packer_result.is_packed}[/red]")
    console.print(f"  Suspicion: [yellow]{packer_result.suspicion_score:.2f}[/yellow]")
    _print_packer_results(packer_result.to_dict())

    # Phase 2: Sandbox execution
    sandbox_result_dict: Optional[dict] = None
    strace_result = None
    gvisor_result = None
    syscall_result: Any = None
    net_result = None
    evasion_dict: Optional[dict] = None
    evasion_events: list[dict] = []
    inotify_log_path: Optional[Path] = None
    sandbox_error: Optional[str] = None
    emulation_result_dict: Optional[dict] = None
    emulation_events: list[dict] = []
    emulation_error: Optional[str] = None
    if not no_sandbox:
        console.print("\n[bold]▸ Phase 2: Sandbox Execution[/bold]")
        try:
            from engine.sandbox.container import ContainerManager, ContainerConfig

            config = ContainerConfig(timeout=timeout)
            manager = ContainerManager(config)

            ready, problems = manager.readiness()
            probe = manager.isolation
            tier_name = probe.selected.name if probe.selected else "unknown"
            if probe.selected and probe.selected.is_security_boundary:
                console.print(
                    f"  Isolation: [green]tier {int(probe.tier)} ({tier_name}, runtime={probe.runtime})[/green]"
                )
            else:
                console.print(
                    f"  Isolation: [yellow]tier {int(probe.tier)} ({tier_name}, runtime={probe.runtime})[/yellow]"
                )
                console.print("  [yellow]⚠ No hardware boundary: the sample shares your host kernel.[/yellow]")

            if ready:
                console.print("  [green]Sandbox ready — detonating sample[/green]")
                sandbox_result = manager.execute(file, results_dir / "sandbox")
                sandbox_result_dict = sandbox_result.to_dict()

                status_color = "green" if sandbox_result.status == "completed" else "red"
                console.print(f"  Status: [{status_color}]{sandbox_result.status}[/{status_color}]")
                console.print(f"  Duration: [cyan]{sandbox_result.duration_seconds:.1f}s[/cyan]")
                console.print(f"  Exit code: [cyan]{sandbox_result.exit_code}[/cyan]")

                if sandbox_result.error:
                    console.print(f"  [red]Error: {sandbox_result.error}[/red]")

                syscall_result, gvisor_result = _parse_syscall_log(
                    sandbox_result, stage_errors
                )

                if syscall_result is not None:
                    console.print(f"  Network connections: [red]{len(syscall_result.network_connections)}[/red]")
                    console.print(f"  Process operations: [red]{len(syscall_result.process_operations)}[/red]")

                # The gVisor Sentry trace is container-wide: the entrypoint,
                # strace, inotifywait and tcpdump all appear. Attribute the
                # events to the sample's process subtree before scoring or
                # normalising, and record what was excluded (D17).
                if gvisor_result is not None:
                    from engine.monitor.attribution import attribute_to_sample

                    scoped_events, attribution = attribute_to_sample(
                        gvisor_result.events, sample_name=sample_name
                    )
                    gvisor_result = dataclasses.replace(
                        gvisor_result,
                        events=scoped_events,
                        parsed_events=len(scoped_events),
                    )
                    syscall_result = gvisor_result
                    if sandbox_result_dict is not None:
                        monitoring = sandbox_result_dict.setdefault("monitoring", {})
                        monitoring["trace_attribution"] = attribution.to_dict()
                    console.print(
                        f"  Attribution: [cyan]{attribution.included}[/cyan] sample events, "
                        f"[dim]{attribution.excluded} excluded[/dim]"
                    )

                if syscall_result is not None:
                    # Evasion is a first-class signal. A recon-heavy but
                    # impact-free run is evasive, not clean.
                    from engine.monitor.evasion import analyze_evasion

                    evasion_report = analyze_evasion(syscall_result)
                    evasion_dict = evasion_report.to_dict()
                    evasion_events = evasion_report.normalized_events()
                    evasion_color = (
                        "red" if evasion_report.verdict == "evasive"
                        else "yellow" if evasion_report.verdict == "suspicious"
                        else "green"
                    )
                    console.print(
                        f"  Evasion score: [{evasion_color}]"
                        f"{evasion_report.score}/100 ({evasion_report.verdict})[/{evasion_color}]"
                    )
                    for finding in evasion_report.findings:
                        console.print(
                            f"    • [{finding.severity.value}] "
                            f"{finding.signal.value} x{finding.count}"
                        )
                    if evasion_report.inconclusive:
                        console.print(
                            "  [red]⚠ Recon-then-quiet: reported as evasive/"
                            "INCONCLUSIVE, not clean.[/red]"
                        )

                # Filesystem events recorded by inotifywait
                if sandbox_result.artifacts and sandbox_result.artifacts.inotify_log:
                    inotify_path = sandbox_result.artifacts.inotify_log
                    line_count = guarded(
                        "inotify log read",
                        stage_errors,
                        functools.partial(_inotify_line_count, inotify_path),
                    )
                    if line_count is None:
                        # Do not hand the same unreadable log to the event
                        # normaliser: it would re-read it and fail again, this
                        # time outside any stage.
                        inotify_log_path = None
                    else:
                        inotify_log_path = inotify_path
                        console.print(f"  Filesystem events: [red]{line_count}[/red]")

                # Analyze network capture if available
                if sandbox_result.tcpdump_pcap:
                    from engine.monitor.network_capture import NetworkCapture
                    console.print("\n  [bold]Analyzing network capture...[/bold]")
                    net_capture = NetworkCapture()
                    pcap_path = Path(sandbox_result.tcpdump_pcap)
                    if pcap_path.exists():
                        net_result = guarded(
                            "PCAP analysis",
                            stage_errors,
                            functools.partial(net_capture.analyze_pcap, pcap_path),
                        )
                        if net_result is not None:
                            console.print(
                                f"  Connections: [cyan]{len(net_result.connections)}[/cyan]"
                            )
                            console.print(
                                f"  DNS queries: [cyan]{len(net_result.dns_queries)}[/cyan]"
                            )
                            console.print(
                                f"  C2 detections: [red]{len(net_result.c2_detections)}[/red]"
                            )

                if sandbox_result.error:
                    sandbox_error = sandbox_result.error
            else:
                console.print("  [yellow]Sandbox not ready — skipping detonation[/yellow]")
                for problem in problems:
                    console.print(f"    • [yellow]{problem}[/yellow]")
        except Exception as e:
            console.print(f"  [red]Sandbox error: {e}[/red]")
            sandbox_error = str(e)

    # Phase 3: Windows PE emulation (separate, declared, containerized stage).
    # This is not isolation and it is fail-closed: a crash, timeout or
    # unimplemented API is INCONCLUSIVE, never a clean verdict (D21).
    if emulate:
        console.print("\n[bold]▸ Phase 3: Windows PE Emulation[/bold]")
        try:
            from engine.emulate.manager import EmulationContainerConfig, EmulationManager

            emu_manager = EmulationManager(EmulationContainerConfig(
                emulate_timeout=emulate_timeout,
                raw=emulate_raw,
                run_capa=not no_emulate_capa,
                allow_host_emulation=allow_host_emulation,
            ))
            emu_result = emu_manager.execute(file, results_dir / "emulation")
            emulation_result_dict = emu_result.section
            emulation_events = emu_result.events
            section = emulation_result_dict or {}
            if emu_result.status == "completed" and section.get("available"):
                if emu_result.ran_on_host:
                    console.print(
                        "  [red]⚠ Ran on the BARE HOST via --allow-host-emulation: "
                        "not containerized, not supported.[/red]"
                    )
                console.print(
                    f"  Emulator: [cyan]{section.get('emulator')} "
                    f"{section.get('emulator_version')}[/cyan] "
                    f"(report schema {str(section.get('schema_hash', ''))[:12]})"
                )
                console.print(
                    f"  API calls: [cyan]{section.get('api_calls', 0)}[/cyan]; "
                    f"events: [cyan]{section.get('events_written', 0)}[/cyan]"
                )
                emu_config = section.get("config") or {}
                endpoints = emu_config.get("network_endpoints") or []
                if endpoints:
                    console.print(f"  Endpoints: [red]{len(endpoints)}[/red]")
                    for endpoint in endpoints[:5]:
                        console.print(
                            f"    • [red]{endpoint.get('server')}:{endpoint.get('port')}[/red] "
                            f"({endpoint.get('protocol')})"
                        )
                if emu_config.get("mutexes"):
                    console.print(
                        f"  Mutexes: [yellow]{', '.join(emu_config['mutexes'])}[/yellow]"
                    )
                snapshots = section.get("snapshots") or {}
                caps = (section.get("capa_dynamic") or {}).get("capabilities") or []
                console.print(
                    f"  capa_dynamic: [cyan]{len(caps)}[/cyan] capability(ies) over "
                    f"[cyan]{snapshots.get('regions_decoded', 0)}[/cyan] snapshot region(s)"
                )
                if section.get("unsupported_apis"):
                    console.print(
                        "  [red]INCONCLUSIVE (emulation): unimplemented API(s): "
                        f"{', '.join(map(str, section['unsupported_apis']))}[/red]"
                    )
                    emulation_error = "emulation inconclusive: unimplemented API handler"
            else:
                console.print(
                    f"  [yellow]Emulation {emu_result.status or 'not run'}: "
                    f"{emu_result.error or 'see limitations'}[/yellow]"
                )
                if emu_result.status in ("error", "unavailable"):
                    emulation_error = emu_result.error
        except Exception as e:  # noqa: BLE001 - an emulation failure must not kill the run
            console.print(f"  [red]Emulation error: {e}[/red]")
            emulation_error = str(e)
            from engine.emulate.runner import unavailable_section as _unavailable

            emulation_result_dict = _unavailable(str(e))
            emulation_result_dict["status"] = "error"

    # IOC Extraction
    console.print("\n[bold]▸ IOC Extraction[/bold]")
    extractor = IOCExtractor()

    static_data = {
        "strings": strings.to_dict(),
        "yara": yara_result.to_dict(),
        "capa": capa_result.to_dict(),
        "packer": packer_result.to_dict(),
        "delivery": delivery_dict,
        # Binary structure, when the sample is one of the two formats HATCHERY
        # parses. ``is_valid_*`` is checked so a parse failure is not published
        # as an empty-but-valid section; the error goes to ``bundle.errors``.
        "pe": pe_result.to_dict() if (pe_result is not None and pe_result.is_valid_pe) else None,
        "elf": elf_result.to_dict() if (elf_result is not None and elf_result.is_valid_elf) else None,
    }

    binary_errors: list[str] = []
    # A guard failure already put a precise "<stage>: unexpected <Type>: ..."
    # entry in ``stage_errors``; the generic line is only for an analyzer that
    # returned an invalid result on its own terms.
    if metadata.file_type == "PE" and pe_result is not None and static_data["pe"] is None:
        binary_errors.append(
            "PE analysis produced no metadata: "
            f"{getattr(pe_result, 'error', None) or 'analyzer did not run'}"
        )
    if metadata.file_type == "ELF" and elf_result is not None and static_data["elf"] is None:
        binary_errors.append(
            "ELF analysis produced no metadata: "
            f"{getattr(elf_result, 'error', None) or 'analyzer did not run'}"
        )

    ioc_report = guarded(
        "IOC extraction",
        stage_errors,
        lambda: extractor.extract(
            static_data=static_data, emulation_data=emulation_result_dict
        ),
        fallback_factory=IOCReport,
    )
    assert ioc_report is not None, "the fallback above is never None"
    _print_iocs(ioc_report.to_dict())

    # MITRE ATT&CK mapping
    console.print("\n[bold]▸ MITRE ATT&CK Mapping[/bold]")
    mapper = MITREMapper()
    mapped_events = None
    if syscall_result is not None:
        mapped_events = syscall_result
    file_watch_data = None
    if inotify_log_path is not None:
        file_watch_data = guarded(
            "filesystem event parse",
            stage_errors,
            functools.partial(_inotify_events, inotify_log_path),
        )
    mitre_result = mapper.map_all(
        capa_data=capa_result.to_dict(),
        yara_data=yara_result.to_dict(),
        behavior_result=mapped_events,
        file_watch_data=file_watch_data,
    )
    if mitre_result.errors:
        console.print(
            f"  [red]⚠ {len(mitre_result.errors)} ATT&CK mapping(s) rejected by the "
            f"pinned ATT&CK {mitre_result.attack_version} dataset[/red]"
        )
        for problem in mitre_result.errors[:5]:
            console.print(f"    • [red]{problem}[/red]")
    if mitre_result.technique_count > 0:
        table = Table(title="ATT&CK Techniques", show_header=True)
        table.add_column("Tactic", style="cyan")
        table.add_column("ID", style="yellow")
        table.add_column("Technique", style="red")
        table.add_column("Source", style="dim")

        for tech in mitre_result.techniques:
            table.add_row(tech.tactic, tech.technique_id, tech.technique_name, tech.source)

        console.print(table)
    else:
        console.print("[dim]No ATT&CK techniques mapped[/dim]")

    # Unified behavioral event stream: syscalls + filesystem + network + evasion
    events = normalize_events(
        strace_result=strace_result,
        gvisor_result=gvisor_result,
        inotify_log=inotify_log_path,
        net_result=net_result,
        evasion_events=evasion_events,
    )

    # One bundle, one source of truth. Everything downstream — the API, the
    # dashboard, future exporters — reads these two files.
    console.print("\n[bold]▸ Result Bundle[/bold]")
    limitations = compute_limitations(
        isolation=sandbox_result_dict.get("isolation") if sandbox_result_dict else None,
        sandbox=sandbox_result_dict,
        artifacts=sandbox_result_dict.get("artifacts") if sandbox_result_dict else None,
        events=events,
        evasion=evasion_dict,
        delivery=delivery_dict,
        emulation=emulation_result_dict,
    )
    bundle = AnalysisBundle(
        task_id=task_id,
        sample={
            "file_name": sample_name,
            "file_path": recorded_path,
            "file_size": hash_result.file_size,
            "file_type": metadata.file_type,
            "store": store_record,
            **hash_result.to_dict(),
        },
        isolation=sandbox_result_dict.get("isolation") if sandbox_result_dict else None,
        static=static_data,
        sandbox=sandbox_result_dict,
        iocs=ioc_report.to_dict().get("iocs", []),
        mitre=mitre_result.to_dict(),
        evasion=evasion_dict,
        emulation=emulation_result_dict,
        events=events,
        emulation_events=emulation_events,
        limitations=limitations,
        # D39: a stage that hit an unexpected exception is named here, in the
        # one list every reader already treats as "this run did not establish
        # that". A guarded failure never silently becomes an empty section.
        errors=[
            e for e in (sandbox_error, emulation_error, *stage_errors, *binary_errors) if e
        ],
    )

    # Local LLM triage (D22). Opt-in, because it costs a model call and needs
    # Ollama; the standalone `hatchery triage <run_dir>` does the same on an
    # existing run. Triage is advisory and grounded — it never replaces the
    # engine's findings, and a failed triage is INCONCLUSIVE, not "clean".
    triage_section = None
    if triage_enabled:
        from engine.triage.triage import TriageConfig, run_triage

        console.print("\n[bold]▸ AI Triage (local model)[/bold]")
        triage_config = TriageConfig.from_env()
        if triage_model:
            triage_config.model = triage_model
        triage_config.allow_remote = allow_remote_model
        triage_config.allow_cloud_model = allow_remote_model
        triage_section = run_triage(bundle.to_dict(), events, config=triage_config)
        if triage_section.get("available"):
            console.print(
                f"  Verdict: [cyan]{triage_section['verdict']}[/cyan] "
                f"(model confidence {triage_section['confidence']}/100, "
                f"{len(triage_section['findings'])} grounded finding(s), "
                f"{triage_section['findings_dropped']} dropped)"
            )
            if triage_section.get("techniques"):
                console.print(
                    f"  Model-suggested techniques: "
                    f"{', '.join(triage_section['techniques'])}"
                )
        else:
            console.print(f"  [red]Triage {triage_section['status']}: {triage_section['reason']}[/red]")
        bundle.triage = triage_section
        # Recompute so the triage limitations are part of the single list.
        bundle.limitations = compute_limitations(
            isolation=sandbox_result_dict.get("isolation") if sandbox_result_dict else None,
            sandbox=sandbox_result_dict,
            artifacts=sandbox_result_dict.get("artifacts") if sandbox_result_dict else None,
            events=events,
            evasion=evasion_dict,
            delivery=delivery_dict,
            emulation=emulation_result_dict,
            triage=triage_section,
        )
        limitations = bundle.limitations

    analysis_path, events_path = write_bundle(results_dir / "bundle", bundle)
    summary = bundle.summary()
    console.print(f"  Events: [cyan]{summary['events_total']}[/cyan] {summary['events_by_category']}")
    console.print(f"  IOCs: [cyan]{summary['iocs_total']}[/cyan] ({summary['iocs_high_or_critical']} high/critical)")
    if summary.get("delivery_format") and summary["delivery_format"] != "unknown":
        console.print(
            f"  Delivery: [cyan]{summary['delivery_format']}[/cyan] "
            f"({summary['delivery_children']} extracted, "
            f"{summary['delivery_unsupported']} unsupported)"
        )
    if summary["evasive"]:
        console.print(
            f"  [red]Evasion: score {summary['evasion_score']}/100 "
            f"({summary['evasion_verdict']}) signals={summary['evasion_signals']}[/red]"
        )
    if summary.get("emulation_available"):
        console.print(
            f"  Emulation: [cyan]{summary['emulation_status']}[/cyan] "
            f"({summary['emulation_api_calls']} API call(s), "
            f"{summary['emulation_endpoints']} endpoint(s), "
            f"{summary['capa_dynamic_capabilities']} dynamic capa)"
        )
        if summary.get("emulation_inconclusive"):
            console.print(
                "  [red]INCONCLUSIVE (emulation): not established, not clean.[/red]"
            )
    console.print(f"  analysis.json: [cyan]{analysis_path}[/cyan]")
    console.print(f"  events.jsonl:  [cyan]{events_path}[/cyan]")
    if summary["evasion_inconclusive"]:
        console.print(
            "  [red]INCONCLUSIVE (evasive): sample reconnoitered and exited with no "
            "observable impact.[/red]"
        )
    elif summary["inconclusive"]:
        console.print("  [red]INCONCLUSIVE: no behavioral events were recorded.[/red]")

    # Human-readable report, generated from the same data
    report_gen = ReportGenerator()
    report_dir = report_gen.write_report(
        results_dir,
        sample_name=sample_name,
        sample_hash=hash_result.to_dict(),
        static_results=static_data,
        sandbox_results=sandbox_result_dict,
        ioc_report=ioc_report.to_dict(),
        limitations=limitations,
        events=events,
        evasion=evasion_dict,
        attack_version=mitre_result.attack_version,
        ocsf_schema_version=OCSF_SCHEMA_VERSION,
        emulation=emulation_result_dict,
        triage=triage_section,
    )
    console.print(f"  Markdown: [cyan]{report_dir / 'report.md'}[/cyan]")

    # STIX export
    stix_exporter = STIXExporter()
    stix_bundle = stix_exporter.export_iocs(ioc_report.to_dict())
    stix_path = results_dir / "stix_bundle.json"
    stix_path.write_text(stix_bundle, encoding="utf-8")
    console.print(f"  STIX 2.1: [cyan]{stix_path}[/cyan]")

    # ATT&CK Navigator layer and OCSF Detection Findings: the same validated
    # mapping, in the two interoperable shapes analysts actually consume.
    from engine.export.attack_navigator import build_navigator_layer, validate_navigator_layer
    from engine.export.ocsf_export import build_ocsf_findings, validate_all as validate_ocsf

    navigator_layer = build_navigator_layer(
        mitre=mitre_result.to_dict(),
        sample_name=sample_name,
        task_id=task_id,
    )
    navigator_errors = validate_navigator_layer(navigator_layer)
    if navigator_errors:
        for problem in navigator_errors:
            console.print(f"  [red]Navigator layer error: {problem}[/red]")
    navigator_path = results_dir / "attack-navigator.json"
    navigator_path.write_text(json.dumps(navigator_layer, indent=2), encoding="utf-8")
    console.print(f"  ATT&CK Navigator: [cyan]{navigator_path}[/cyan]")

    ocsf_findings = build_ocsf_findings(
        task_id=task_id,
        sample_name=sample_name,
        mitre=mitre_result.to_dict(),
        evasion=evasion_dict,
        events=events,
        summary=summary,
        limitations=limitations,
    )
    ocsf_errors = validate_ocsf(ocsf_findings)
    if ocsf_errors:
        for problem in ocsf_errors:
            console.print(f"  [red]OCSF finding error: {problem}[/red]")
    ocsf_path = results_dir / "ocsf.json"
    ocsf_path.write_text(json.dumps(ocsf_findings, indent=2), encoding="utf-8")
    console.print(f"  OCSF (Detection Finding): [cyan]{ocsf_path}[/cyan]")

    # Candidate Sigma rules: generated drafts, clearly labelled and unreviewed.
    from engine.export.sigma_candidates import (
        build_sigma_candidates,
        validate_sigma_rule,
        write_sigma_candidates,
    )

    sigma_rules = build_sigma_candidates(
        mitre=mitre_result.to_dict(),
        events=events,
        task_id=task_id,
        sample_name=sample_name,
        attack_version=mitre_result.attack_version,
    )
    sigma_errors = [p for rule in sigma_rules for p in validate_sigma_rule(rule)]
    for problem in sigma_errors:
        console.print(f"  [red]Sigma candidate error: {problem}[/red]")
    sigma_dir = write_sigma_candidates(results_dir, sigma_rules)
    if sigma_dir is not None:
        console.print(
            f"  Candidate Sigma: [cyan]{sigma_dir}[/cyan] "
            f"({len(sigma_rules)} generated draft(s), review required)"
        )

    # Save task data
    task_data["status"] = "completed"
    task_data["end_time"] = time.time()
    task_data["results_dir"] = str(results_dir)
    _tasks[task_id] = task_data

    # The staging file for a --from-store run is removed here and by an atexit
    # hook; nothing plaintext survives the run in the store or the results tree.
    # Closing first also means a seal failure below cannot leave the staging file
    # (and the decrypted sample) behind.
    if staged is not None:
        staged.close()
    sample_store.close()

    # D33: the manifest is written last, after every other file the run produced
    # and after every writer has finished. It hashes the run as of this stage, so
    # triage and push re-seal rather than reporting a legitimate change as a
    # break. A seal that cannot be written is loud: an unsealed run is not the
    # artifact this tool promises, and shipping it silently would make `verify`
    # a lie by omission.
    from engine.results import ManifestError, seal_run as seal_result_run

    try:
        manifest = seal_result_run(results_dir, stage="submit")
    except ManifestError as exc:
        console.print(
            f"[red]Cannot seal the run: {exc.reason}: {exc.message}[/red]\n"
            "[red]The analysis is on disk but has no manifest, so it is not a "
            "verified result. Resolve the cause and run `hatchery results seal "
            f"{results_dir}`.[/red]"
        )
        raise SystemExit(1) from exc

    if limitations:
        console.print(render_limitations(limitations), highlight=False)

    console.print(Panel(
        f"Task ID: [cyan]{task_id}[/cyan]\n"
        f"Status: [green]completed[/green]\n"
        f"Results: [cyan]{results_dir}[/cyan]\n"
        f"Manifest: [cyan]{manifest['manifest_sha256']}[/cyan]",
        title="✅ Analysis Complete",
    ))
    console.print(
        "  Verify or deliver this run with: "
        f"[dim]hatchery results verify {results_dir}[/dim]"
    )


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--timeout", default=180, help="Container wall-clock timeout in seconds")
@click.option("--emulate-timeout", default=60, help="Emulated-run timeout in seconds")
@click.option("--no-capa", is_flag=True, help="Skip capa over memory snapshots")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output directory")
@click.option("--allow-host-emulation", is_flag=True, help="Escape hatch: run on the bare host (loudly unsupported)")
@click.pass_context
def emulate(
    ctx: click.Context,
    file: Path,
    timeout: int,
    emulate_timeout: int,
    no_capa: bool,
    output: Optional[Path],
    allow_host_emulation: bool,
) -> None:
    """Emulate a Windows PE with Speakeasy (standalone).

    Runs the static pipeline plus the containerized emulation stage, without
    detonation. Use ``hatchery submit --emulate`` to run both. Emulation is a
    declared stage, not an isolation boundary, and it is fail-closed.
    """
    ctx.invoke(
        submit,
        file=file,
        timeout=timeout,
        output=output,
        no_sandbox=True,
        emulate=True,
        emulate_timeout=emulate_timeout,
        emulate_raw=False,
        no_emulate_capa=no_capa,
        allow_host_emulation=allow_host_emulation,
    )


@cli.command()
@click.argument("task_id")
def status(task_id: str) -> None:
    """Check the status of an analysis task."""
    if task_id in _tasks:
        task = _tasks[task_id]
        console.print(Panel(
            f"Task ID: [cyan]{task_id}[/cyan]\n"
            f"Status: [green]{task['status']}[/green]\n"
            f"File: {task.get('file', 'N/A')}\n"
            f"Results: {task.get('results_dir', 'N/A')}",
            title="Task Status",
        ))
    else:
        console.print(f"[red]Task {task_id} not found[/red]")
        console.print("[dim]Active tasks:[/dim]")
        for tid, t in _tasks.items():
            console.print(f"  {tid}: {t['status']}")


@cli.command()
@click.argument("task_id")
@click.option("--format", "fmt", type=click.Choice(["markdown", "json", "stix", "navigator", "ocsf"]), default="markdown")
def report(task_id: str, fmt: str) -> None:
    """Generate an analysis report for a completed task."""
    if task_id not in _tasks:
        console.print(f"[red]Task {task_id} not found[/red]")
        return

    task = _tasks[task_id]
    results_dir = Path(task.get("results_dir", ""))

    if fmt == "markdown" and (results_dir / "report.md").exists():
        console.print((results_dir / "report.md").read_text())
    elif fmt == "json" and (results_dir / "report.json").exists():
        console.print_json((results_dir / "report.json").read_text())
    elif fmt == "stix" and (results_dir / "stix_bundle.json").exists():
        console.print_json((results_dir / "stix_bundle.json").read_text())
    elif fmt == "navigator" and (results_dir / "attack-navigator.json").exists():
        console.print_json((results_dir / "attack-navigator.json").read_text())
    elif fmt == "ocsf" and (results_dir / "ocsf.json").exists():
        console.print_json((results_dir / "ocsf.json").read_text())
    else:
        console.print(f"[red]Report not found for task {task_id}[/red]")


@cli.command()
@click.argument("task_id")
@click.option("--format", "fmt", type=click.Choice(["json", "stix"]), default="json")
def iocs(task_id: str, fmt: str) -> None:
    """Extract IOCs from a completed analysis."""
    if task_id not in _tasks:
        console.print(f"[red]Task {task_id} not found[/red]")
        return

    task = _tasks[task_id]
    results_dir = Path(task.get("results_dir", ""))

    if fmt == "stix" and (results_dir / "stix_bundle.json").exists():
        console.print_json((results_dir / "stix_bundle.json").read_text())
    elif (results_dir / "report.json").exists():
        report_data = json.loads((results_dir / "report.json").read_text())
        ioc_data = report_data.get("ioc_report", {})
        _print_iocs(ioc_data)
    else:
        console.print(f"[red]No results found for task {task_id}[/red]")


@cli.command()
@click.argument("run_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--target", "target_kind", type=click.Choice(["misp", "opencti"]), required=True)
@click.option("--url", default=None, help="Platform base URL (else HATCHERY_<TARGET>_URL)")
@click.option("--token", default=None, help="API token (else the environment)")
@click.option("--collection", default=None, help="OpenCTI TAXII collection id")
@click.option("--insecure", is_flag=True, help="Skip TLS verification (warns loudly)")
@internal_error_backstop
def push(run_dir: Path, target_kind: str, url: Optional[str], token: Optional[str],
         collection: Optional[str], insecure: bool) -> None:
    """Push a run's STIX bundle to MISP or OpenCTI.

    Reads the ``stix_bundle.json`` the engine already wrote — it does not
    re-derive STIX, so there is still exactly one producer. Fail-closed: a
    non-2xx response or a transport error is reported and exits non-zero.
    """
    from engine.export.push import PushTarget, push_stix, write_push_result

    _require_verifiable_stage(run_dir)
    bundle_path = run_dir / "stix_bundle.json"
    if not bundle_path.exists():
        console.print(f"[red]No stix_bundle.json in {run_dir} — run an analysis first.[/red]")
        raise SystemExit(1)
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))

    if url and token:
        if target_kind == "opencti":
            coll = collection or os.environ.get("HATCHERY_OPENCTI_COLLECTION", "").strip()
            if not coll:
                console.print(
                    "[red]OpenCTI push needs --collection "
                    "(or HATCHERY_OPENCTI_COLLECTION).[/red]"
                )
                raise SystemExit(1)
            target: Optional[PushTarget] = PushTarget.opencti(
                url, token, coll, verify_tls=not insecure
            )
        else:
            target = PushTarget.misp(url, token, verify_tls=not insecure)
    else:
        env_target = PushTarget.from_env(target_kind)
        if env_target is None:
            console.print(
                f"[red]No credentials for {target_kind}.[/red] Pass --url/--token"
                + (" and --collection" if target_kind == "opencti" else "")
                + f", or set the HATCHERY_{target_kind.upper()}_* environment variables."
            )
            raise SystemExit(1)
        if insecure:
            env_target.verify_tls = False
        target = env_target

    if target is None:  # unreachable; narrows the type for the checker
        raise SystemExit(1)

    if not target.verify_tls:
        console.print("[yellow]⚠ TLS verification is disabled for this push.[/yellow]")

    result = push_stix(bundle, target)
    result_path = write_push_result(run_dir, target, result)
    _reseal_after_stage(run_dir, "push")
    if result.ok:
        console.print(
            f"[green]✓ Pushed {result.objects} STIX object(s) to "
            f"{target_kind}[/green] — {result.url}"
        )
        console.print(f"  Result recorded: [cyan]{result_path}[/cyan]")
        return

    console.print(f"[red]✗ Push to {target_kind} failed:[/red] {result.message}")
    console.print(f"  Result recorded: [cyan]{result_path}[/cyan]")
    raise SystemExit(1)


@cli.command()
@click.argument("run_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--model", default=None, help="Ollama model to use (else HATCHERY_TRIAGE_MODEL or auto-pick)")
@click.option("--allow-remote-model", is_flag=True, help="Escape hatch: allow a remote endpoint or a `:cloud` model to see sample text")
@click.option("--timeout", default=180.0, help="Per-request timeout in seconds")
@internal_error_backstop
def triage(run_dir: Path, model: Optional[str], allow_remote_model: bool, timeout: float) -> None:
    """Run local LLM triage over an existing run's bundle.

    RUN_DIR may be the run directory (``results/<run>``) or its ``bundle/``;
    both are natural things to type and both resolve to the run root for the
    re-seal. Reads `analysis.json` and `events.jsonl`, asks a local Ollama model
    for a grounded triage, and writes the result back into the bundle. Advisory
    only: every claim must cite evidence that exists in the run, and a triage
    that cannot be grounded is INCONCLUSIVE, not clean.
    """
    from engine.bundle import BundleReadError, attach_triage, load_bundle, load_events
    from engine.results import ManifestError, resolve_run_root
    from engine.triage.triage import TriageConfig, run_triage

    try:
        run_root = resolve_run_root(run_dir)
    except ManifestError as exc:
        console.print(f"[red]{exc.reason}: {exc.message}[/red]")
        raise SystemExit(1) from exc
    bundle_dir = (
        run_root / "bundle"
        if (run_root / "bundle" / "analysis.json").is_file()
        else run_root
    )
    _require_verifiable_stage(run_root)
    try:
        bundle = load_bundle(bundle_dir)
        events = load_events(bundle_dir)
    except (FileNotFoundError, BundleReadError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1) from exc

    config = TriageConfig.from_env()
    if model:
        config.model = model
    config.allow_remote = allow_remote_model
    config.allow_cloud_model = allow_remote_model
    config.timeout = timeout

    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Local LLM triage\n"
            f"Run: [cyan]{run_root}[/cyan]\n"
            f"Evidence: {len(events)} event(s) in the bundle",
            title="🔍 AI Triage",
        )
    )

    section = run_triage(bundle, events, config=config)
    if section.get("available"):
        console.print(
            f"  Model: [cyan]{section['model']}[/cyan] "
            f"(prompt contract {section['prompt_version']})"
        )
        console.print(
            f"  Verdict: [cyan]{section['verdict']}[/cyan] "
            f"(confidence {section['confidence']}/100)"
        )
        if section.get("summary"):
            console.print(f"  {section['summary']}")
        for finding in section.get("findings") or []:
            console.print(
                f"    • {finding['claim']} [dim]← {', '.join(finding['grounding'])}[/dim]"
            )
        if section.get("findings_dropped"):
            console.print(
                f"  [yellow]{section['findings_dropped']} finding(s) dropped: "
                "citations did not resolve to evidence in this run[/yellow]"
            )
        if section.get("techniques"):
            console.print(
                f"  Model-suggested ATT&CK: [yellow]{', '.join(section['techniques'])}"
                "[/yellow] [dim](unvalidated association)[/dim]"
            )
        for item in section.get("not_established") or []:
            console.print(f"  [dim]not established: {item}[/dim]")
    else:
        console.print(f"  [red]Triage {section['status']}: {section['reason']}[/red]")

    path = attach_triage(bundle_dir, section)
    _reseal_after_stage(run_root, "triage")
    console.print(f"  Bundle updated: [cyan]{path}[/cyan]")
    if not section.get("available"):
        raise SystemExit(1)


@cli.command()
@click.argument("path", type=click.Path(path_type=Path), default=Path("results"), required=False)
@click.option("--threshold", default=0.5, type=float, help="Minimum similarity to group two runs (0-1)")
@click.option("--min-size", default=2, type=int, help="Smallest cluster to report")
@click.option("--limit", default=None, type=int, help="Cap the number of runs scanned")
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Write clusters.json to this path")
@internal_error_backstop
def cluster(path: Path, threshold: float, min_size: int, limit: Optional[int],
            as_json: bool, output: Optional[Path]) -> None:
    """Group analysed runs that look like the same campaign.

    Reads every `analysis.json` under PATH (default `results/`), fingerprints each
    run from what the engine already recorded, and groups runs whose similarity
    is at least --threshold. Similarity is not attribution: a cluster is a lead to
    investigate, never a family name.
    """
    from engine.cluster.cluster import build_clusters

    root = Path(path)
    if not root.exists():
        console.print(f"[red]No such path: {root}[/red]")
        raise SystemExit(1)

    try:
        clusters, fingerprints, stats = build_clusters(
            root, threshold=threshold, min_size=min_size, limit=limit
        )
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(1)

    payload = {
        "root": str(root),
        "stats": stats,
        "clusters": [cluster_obj.to_dict() for cluster_obj in clusters],
        "runs": [fingerprint.to_dict() for fingerprint in fingerprints],
    }
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    if as_json:
        console.print_json(json.dumps(payload, default=str))
        return

    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Campaign clustering\n"
            f"Root: [cyan]{root}[/cyan]\n"
            f"Runs: {stats['runs_scanned']}  ·  Clusters: {stats['clusters']}  ·  "
            f"Grouped: {stats['clustered_runs']}  ·  Ungrouped: {stats['unclustered_runs']}",
            title="🔗 Clusters",
        )
    )
    if not fingerprints:
        console.print("[yellow]No analysed runs found under this path.[/yellow]")
        return
    if not clusters:
        console.print(
            f"[dim]No cluster at or above {threshold:.2f} similarity. "
            "Lower --threshold to widen the net.[/dim]"
        )
        return

    for cluster_obj in clusters:
        if cluster_obj.identical_bytes:
            score_text = "byte-identical sample"
        else:
            score_text = (
                f"score {cluster_obj.min_score:.2f}\u2013{cluster_obj.max_score:.2f}"
            )
        console.print(
            f"\n[bold]Cluster {cluster_obj.cluster_id}[/bold] "
            f"({cluster_obj.size} run(s), {score_text}, "
            f"representative [cyan]{cluster_obj.representative[:12]}[/cyan])"
        )
        table = Table(show_header=True, header_style="bold")
        table.add_column("Task", style="cyan")
        table.add_column("Sample")
        table.add_column("Type", style="dim")
        table.add_column("SHA256", style="dim")
        for member in cluster_obj.members:
            table.add_row(
                member.task_id[:12] or "-",
                member.file_name or "-",
                member.file_type or "-",
                (member.sha256[:16] + "\u2026") if member.sha256 else "-",
            )
        console.print(table)
        if cluster_obj.shared:
            top = cluster_obj.shared[:8]
            console.print(
                "  shared: "
                + ", ".join(
                    f"[yellow]{entry['feature']}[/yellow] ({entry['count']})"
                    for entry in top
                )
            )
    console.print(
        "\n[dim]Similarity is a lead, not attribution: shared features occur in "
        "benign software too. HATCHERY does not name families.[/dim]"
    )


@cli.command()
@click.argument("run_dir", type=click.Path(exists=True, path_type=Path))
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Directory for the replayed run")
@click.option("--no-sandbox", "force_no_sandbox", is_flag=True, help="Replay the static stage only, even if the original detonated")
@click.option("--allow-host-emulation", is_flag=True, help="Escape hatch: emulate on the bare host (loudly unsupported)")
@click.option("--sample", "sample_override", type=click.Path(path_type=Path), default=None, help="Use this copy of the sample (its sha256 must match the bundle)")
@click.option("--timeout", default=1800.0, help="Submit timeout in seconds")
@click.option(
    "--require-manifest", is_flag=True,
    help="Treat an unsealed source run as INCONCLUSIVE (off by default: a legacy run still replays)",
)
@click.option("--json", "as_json", is_flag=True, help="Emit the replay section as JSON")
@internal_error_backstop
def replay(
    run_dir: Path,
    output: Optional[Path],
    force_no_sandbox: bool,
    allow_host_emulation: bool,
    sample_override: Optional[Path],
    timeout: float,
    require_manifest: bool,
    as_json: bool,
) -> None:
    """Re-analyse a run and report whether its static findings reproduce.

    Locates the sample the bundle recorded, re-runs the existing submit pipeline
    with the reproduced settings, and classifies every signal: deterministic
    static facts must be identical or the replay is a loud static-mismatch;
    dynamic observations are reported as drift and never failed on. A replay
    that could not run, or could not reproduce the settings, is INCONCLUSIVE —
    never a silent pass. Exit codes: 0 reproducible/dynamic-drift, 2
    static-mismatch, 1 inconclusive.

    The source run's manifest is checked first (D33). A manifest that does not
    match the run is INCONCLUSIVE naming the classification and the file: a
    verdict about different bytes is a verdict about fiction. A missing manifest
    (a legacy run) replays with the verdict unchanged and
    ``bundle_manifest: unsealed`` recorded; ``--require-manifest`` turns that
    into INCONCLUSIVE for operators who seal everything.
    """
    from engine.replay import DETERMINISTIC_KINDS, ReplayError, run_replay

    # Diagnostics to stderr, always: stdout is the replay section under --json
    # and the human panel otherwise, and a log line must not corrupt either.
    _logs_to_stderr()
    try:
        result = run_replay(
            run_dir,
            output_dir=output,
            force_no_sandbox=force_no_sandbox,
            allow_host_emulation=allow_host_emulation,
            sample_override=sample_override,
            submit_timeout=timeout,
            require_manifest=require_manifest,
        )
    except ReplayError as exc:
        console.print(f"[red]{exc}[/red]")
        raise SystemExit(2)

    section = result.section
    if as_json:
        click.echo(json.dumps(section, indent=2, default=str))
        raise SystemExit(result.exit_code)

    color = {
        "reproducible": "green",
        "dynamic-drift": "yellow",
        "static-mismatch": "red",
        "inconclusive": "yellow",
    }.get(result.verdict, "white")
    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Deterministic replay\n"
            f"Original: [cyan]{section.get('original_task_id') or '(unknown)'}[/cyan]\n"
            f"Replay:   [cyan]{section.get('replay_task_id') or '(did not complete)'}[/cyan]\n"
            f"Verdict:  [{color}]{result.verdict}[/{color}]",
            title="♻ Replay",
        )
    )

    console.print(
        f"  Sample: {section['sample']['path']} "
        f"[dim]({section['sample']['resolution']})"
        + (" [green]hash verified[/green]" if section["sample"]["hash_verified"] else " [red]hash NOT verified[/red]")
    )

    settings = section.get("settings") or {}
    original_settings = settings.get("original") or {}
    replay_settings = settings.get("replay") or {}
    if original_settings and replay_settings:
        table = Table(title="Settings", show_header=True)
        table.add_column("Setting", style="cyan")
        table.add_column("Original")
        table.add_column("Replay")
        table.add_column("Match")
        match = settings.get("match") or {}
        for key in ("dynamic", "emulation", "isolation_tier", "collector"):
            same = match.get(key)
            mark = "[green]✓[/green]" if same else "[red]✗[/red]"
            table.add_row(
                key,
                str(original_settings.get(key)),
                str(replay_settings.get(key)),
                mark,
            )
        console.print(table)

    table = Table(title="Deterministic signs (must be identical)", show_header=True)
    table.add_column("Signal", style="cyan")
    table.add_column("Identical")
    for name in DETERMINISTIC_KINDS:
        same = section.get("identical", {}).get(name)
        if same is True:
            mark = "[green]✓[/green]"
        elif same is False:
            mark = "[red]✗[/red]"
        else:
            mark = "[yellow]? unknown[/yellow]"
        table.add_row(name, mark)
    console.print(table)

    diff = section.get("diff") or {}
    if diff:
        console.print("[bold]Differences[/bold]")
        for name, detail in diff.items():
            if "only_original" in detail:
                console.print(
                    f"  [red]{name}[/red] only-in-original={detail['only_original']} "
                    f"only-in-replay={detail['only_replay']}"
                )
            else:
                console.print(
                    f"  [yellow]{name}[/yellow] original={detail['original']} "
                    f"replay={detail['replay']}"
                )

    if section.get("not_replayed"):
        console.print(f"  [dim]not replayed: {', '.join(section['not_replayed'])}[/dim]")

    console.print(render_limitations(section.get("limitations") or []), highlight=False)
    console.print(
        f"  replay.json: [cyan]{Path(str(section.get('replay_run_dir', ''))) / 'replay.json'}[/cyan]"
    )

    if result.verdict == "static-mismatch":
        console.print("[red]Deterministic static findings did NOT reproduce.[/red]")
    raise SystemExit(result.exit_code)


@cli.command()
@click.option("--once", is_flag=True, help="Drain the queue, then exit")
@click.option("--concurrency", default=1, type=click.IntRange(min=1), help="Maximum jobs in flight at once")
@click.option("--queue", "queue_db", type=click.Path(path_type=Path), default=None, help="Queue database (default: data/queue.db or HATCHERY_QUEUE_DB)")
@click.option("--lease", default=60.0, type=float, help="Lease seconds; a dead worker's job is recovered after this")
@click.option("--poll-interval", default=2.0, type=float, help="Seconds to wait between polls (loop mode)")
@click.option("--timeout", default=1800.0, type=float, help="Per-job submit timeout in seconds")
@click.option("--worker-id", default=None, help="Worker id (default: a fresh id)")
def worker(
    once: bool,
    concurrency: int,
    queue_db: Optional[Path],
    lease: float,
    poll_interval: float,
    timeout: float,
    worker_id: Optional[str],
) -> None:
    """Run a queue worker: execute queued submissions, safely and durably.

    Claims jobs atomically (two workers never run the same job), renews a lease
    while a job runs, and recovers a dead worker's job instead of leaving it
    ``running`` forever. The bundle is the authority: exit code 0 alone is not
    success, so a job without a bundle fails with the reason.

    Run with ``--once`` to drain the queue and exit.
    """
    import threading as _threading

    from engine.queue import JobStore, Worker, WorkerConfig, resolve_queue_db

    db_path = resolve_queue_db(queue_db)
    config = WorkerConfig(
        worker_id=worker_id or WorkerConfig().worker_id,
        concurrency=concurrency,
        lease_seconds=lease,
        poll_interval=poll_interval,
        submit_timeout=timeout,
        once=once,
    )
    store = JobStore(db_path)
    runner_worker = Worker(store, config)
    if once:
        outcomes = runner_worker.run_once()
        if not outcomes:
            console.print("[dim]Queue empty — nothing to do.[/dim]")
            store.close()
            return
        failed = False
        for outcome in outcomes:
            color = "green" if outcome.status == "completed" else "red"
            if outcome.status != "completed":
                failed = True
            console.print(
                f"  [{color}]{outcome.status}[/{color}] job "
                f"[cyan]{outcome.job_id}[/cyan]"
                f"{(' — ' + outcome.detail) if outcome.detail else ''}"
            )
        store.close()
        if failed:
            # A worker that returns 0 while a job failed would be exactly the
            # quiet failure this project exists to avoid.
            raise SystemExit(1)
        return

    stop = _threading.Event()
    try:
        runner_worker.run_forever(stop)
    except KeyboardInterrupt:
        console.print("\n[dim]Worker stopping.[/dim]")
    finally:
        store.close()


@cli.command(name="queue")
@click.argument("job_id", required=False)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON")
@click.option("--status", type=click.Choice(["queued", "running", "completed", "failed"]), default=None, help="Only show jobs in this state")
@click.option("--limit", default=50, type=int, help="Maximum rows to list")
@click.option("--recover", is_flag=True, help="Requeue or fail jobs whose worker lease expired")
@click.option("--requeue", "requeue_job", is_flag=True, help="Re-queue JOB_ID as it is (sample reference, name, output and args kept)")
@click.option("--queue", "queue_db", type=click.Path(path_type=Path), default=None, help="Queue database (default: data/queue.db or HATCHERY_QUEUE_DB)")
def queue_command(
    job_id: Optional[str],
    as_json: bool,
    status: Optional[str],
    limit: int,
    recover: bool,
    requeue_job: bool,
    queue_db: Optional[Path],
) -> None:
    """Show the durable job queue, or one job.

    With no argument, lists jobs (most recent first) and the state counts. With
    a JOB_ID, prints that job. ``--recover`` first requeues (or fails) any job
    whose worker died holding the lease.

    ``--requeue`` re-queues JOB_ID from what the row already records (D42). It is
    how a retry works when the sample never had a path, or when its original path
    has since been deleted — and it keeps the original arguments, so a retry
    cannot silently turn an emulated or static-only job into a different one.
    """
    from engine.queue import JobError, JobStore, resolve_queue_db

    store = JobStore(resolve_queue_db(queue_db))
    try:
        recovered = store.recover_expired() if recover else []
        if requeue_job:
            if not job_id:
                raise click.UsageError("--requeue needs a JOB_ID")
            try:
                requeued = store.requeue(job_id)
            except JobError as exc:
                console.print(f"[red]{exc}[/red]")
                raise SystemExit(1) from exc
            if as_json:
                print(json.dumps(requeued.to_dict(), default=str))
                return
            console.print(
                f"[green]Re-queued[/green] {requeued.job_id} "
                f"(attempts reset, sample {requeued.sample_store_ref or requeued.sample_path})"
            )
            return
        if job_id:
            job = store.get(job_id)
            if job is None:
                console.print(f"[red]No job {job_id} in {store.path}[/red]")
                raise SystemExit(1)
            if as_json:
                console.print_json(json.dumps(job.to_dict(), default=str))
                return
            _print_job(job)
            return

        jobs = store.list(status=status, limit=limit)
        counts = store.counts()
        if as_json:
            console.print_json(json.dumps(
                {
                    "queue_db": store.path,
                    "counts": counts,
                    "recovered": recovered,
                    "jobs": [job.to_dict() for job in jobs],
                },
                default=str,
            ))
            return

        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Job queue\n"
                f"Queue: [cyan]{store.path}[/cyan]\n"
                f"queued {counts['queued']} · running {counts['running']} · "
                f"completed {counts['completed']} · failed {counts['failed']} "
                f"(total {counts['total']})",
                title="Queue",
            )
        )
        for recovered_id in recovered:
            console.print(f"  [yellow]recovered[/yellow] {recovered_id}")
        if not jobs:
            console.print("[dim]No jobs.[/dim]")
            return
        table = Table(show_header=True, header_style="bold")
        table.add_column("Job", style="cyan")
        table.add_column("Status")
        table.add_column("Attempts", style="dim")
        table.add_column("Worker", style="dim")
        table.add_column("Sample")
        table.add_column("Detail", style="dim")
        for job in jobs:
            color = {
                "completed": "green", "failed": "red",
                "running": "yellow", "queued": "blue",
            }.get(job.status, "white")
            table.add_row(
                job.job_id,
                f"[{color}]{job.status}[/{color}]",
                f"{job.attempts}/{job.max_attempts}",
                job.worker_id or "-",
                Path(job.sample_path).name,
                (job.error or "")[:60],
            )
        console.print(table)
    finally:
        store.close()


def _print_job(job: Any) -> None:
    """Render one queue job for a human."""
    color = {
        "completed": "green", "failed": "red",
        "running": "yellow", "queued": "blue",
    }.get(job.status, "white")
    console.print(
        Panel(
            f"Job:      [cyan]{job.job_id}[/cyan]\n"
            f"Status:   [{color}]{job.status}[/{color}]\n"
            f"Sample:   {job.sample_path}\n"
            + (f"Store:    {job.sample_store_ref} (encrypted copy the worker runs)\n"
               if job.sample_store_ref else "")
            + f"Output:   {job.output_dir}\n"
            f"Attempts: {job.attempts}/{job.max_attempts}"
            + (f"  worker={job.worker_id}" if job.worker_id else "")
            + (f"\nLease:    expires {job.lease_expires_at}" if job.lease_expires_at else "")
            + (f"\nRun dir:  {job.run_dir}" if job.run_dir else "")
            + (f"\nError:    [red]{job.error}[/red]" if job.error else ""),
            title="Job",
        )
    )


# ---------------------------------------------------------------------------
# hatchery store — the sample store maintenance group (D28)
# ---------------------------------------------------------------------------

STORE_EXIT_OK = 0
STORE_EXIT_ERROR = 1
STORE_EXIT_FAILURES = 2


def _store_root() -> Path:
    from engine.store import resolve_store_root

    return resolve_store_root()


def _store_command_failed(
    exc: Any, as_json: bool, code: int = STORE_EXIT_ERROR
) -> NoReturn:
    """Report a store error on stderr and exit non-zero — never print key material."""
    reason = getattr(exc, "reason", "error")
    message = getattr(exc, "message", str(exc))
    if as_json:
        click.echo(json.dumps({"ok": False, "reason": reason, "message": message}), err=True)
    else:
        click.echo(f"HATCHERY store: {reason}: {message}", err=True)
    raise SystemExit(code)


def _human_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"  # pragma: no cover


def _store_common_options(function: Any) -> Any:
    """The options every store subcommand shares (root, results, queue, --json)."""
    function = click.option(
        "--queue", "queue_db", type=click.Path(path_type=Path), default=None,
        help="Queue database to read for queued/running job references "
             "(default: data/queue.db or HATCHERY_QUEUE_DB)",
    )(function)
    function = click.option(
        "--results", "results_root", type=click.Path(path_type=Path), default=None,
        help="Results root to scan for run-bundle references (default: discovered)",
    )(function)
    function = click.option(
        "--store", "store_root", type=click.Path(path_type=Path), default=None,
        help="Sample store root (default: HATCHERY_SAMPLE_STORE or <checkout>/samples)",
    )(function)
    function = click.option(
        "--json", "as_json", is_flag=True, help="Emit one JSON object on stdout"
    )(function)
    return function


def _logs_to_stderr() -> None:
    """Keep stdout for the machine-readable object a store command promises.

    The global Rich handler writes to stdout, which would corrupt
    ``hatchery store ... --json`` the moment a prune logs what it deleted.
    Diagnostics for this command group go to stderr instead.
    """
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(
        RichHandler(console=Console(stderr=True), show_time=True, show_path=False)
    )


def _open_store(store_root: Optional[Path]) -> Any:
    from engine.store import SampleStore

    _logs_to_stderr()
    return SampleStore(store_root)


def _resolved_queue_db(queue_db: Optional[Path]) -> Optional[Path]:
    """The queue to read for references, or ``None`` when it does not exist."""
    from engine.queue import resolve_queue_db

    path = resolve_queue_db(queue_db)
    return path if path.is_file() else None


@cli.group()
def store() -> None:
    """Sample store: intake, status, verify, migrate and prune.

    The store is content-addressed by sha256 and encrypted at rest (AES-256-GCM,
    versioned envelope). `put` takes a sample and returns its address — from a
    file, or from a pipe with `--stdin`, which is how the HTTP boundary accepts
    an upload without writing the bytes down (D42). `status` reports counts and
    retention, `verify` decrypts and hash-checks every entry, `migrate` encrypts
    a legacy plaintext store idempotently, and `prune` deletes expired,
    unreferenced samples — dry-run unless --apply.

    Every subcommand accepts --json (one object on stdout; diagnostics on
    stderr). Exit codes: 0 success, 1 operational error, 2 verification or
    retention failure (including a refused prune). No command prints a key.
    """


@store.command("put")
@click.argument("file", type=click.Path(exists=True, dir_okay=False, path_type=Path), required=False)
@click.option("--stdin", "read_stdin", is_flag=True, help="Read the sample bytes from a pipe instead of a FILE")
@click.option("--name", "sample_name", default=None, help="Display name to record for a sample read from --stdin")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
@click.option("--store", "store_root", type=click.Path(path_type=Path), default=None,
              help="Sample store root (default: HATCHERY_SAMPLE_STORE or <checkout>/samples)")
@internal_error_backstop
def store_put(
    file: Optional[Path],
    read_stdin: bool,
    sample_name: Optional[str],
    as_json: bool,
    store_root: Optional[Path],
) -> None:
    """Store a sample and print its content address.

    One job: take the bytes, encrypt them, return the address. It is deliberately
    separate from `submit --enqueue`, which queues an address it is given (D42).
    The HTTP boundary needs that split: it can only know a form's `timeout` and
    `noSandbox` once the whole body has been read, and a body cannot be read and
    *not* written down at the same time unless it is read as it arrives. So the
    stream is consumed here, at once, and the job is queued afterwards by
    `hatchery submit --from-store SHA --enqueue`.

    With ``--stdin`` the sample is read from a pipe under the store's own limit
    (256 MiB) and encrypted from memory: **no plaintext file exists at any
    instant**, at the size limit or any other. A pipe has no ``lstat``, so the
    limit is applied while reading rather than before it (D40's rule cannot run
    in front of a socket), and a refusal stores nothing.
    """
    from engine.store import SampleStoreError
    from engine.store.limits import SampleSourceError, read_sample_stream

    if read_stdin and file is not None:
        raise click.UsageError("--stdin cannot be combined with a FILE")
    if not read_stdin and file is None:
        raise click.UsageError("store put needs a FILE or --stdin")
    if read_stdin and sys.stdin.isatty():
        raise click.UsageError(
            "--stdin reads the sample from a pipe, and no stream is attached to "
            "this terminal; use `cat sample | hatchery store put --stdin`"
        )

    try:
        sample_store = _open_store(store_root)
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
    try:
        if read_stdin:
            try:
                data = read_sample_stream(
                    sys.stdin.buffer, limit=sample_store.max_bytes
                )
            except SampleSourceError as exc:
                _store_command_failed(exc, as_json)
            record = sample_store.put_bytes(
                data, source=f"stdin:{sample_name or 'sample'}"
            )
        else:
            assert file is not None
            record = sample_store.put_file(file)
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
    finally:
        sample_store.close()

    notice = sample_store.generated_key_notice
    if notice:
        click.echo(f"WARNING: {notice}", err=True)
    payload = {
        "ok": True,
        "sha256": record.sha256,
        "size": record.size,
        "blob": record.blob,
        "encrypted": record.encrypted,
    }
    if as_json:
        print(json.dumps(payload))
    else:
        click.echo(f"{record.sha256}  {_human_size(record.size)}  {record.blob}")


@store.command("status")
@_store_common_options
@click.option("--ttl", "ttl_seconds", type=float, default=None,
              help="Retention TTL in seconds for the report (0 disables; default: HATCHERY_SAMPLE_TTL)")
def store_status(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, ttl_seconds: Optional[float],
) -> None:
    """Show sample count/bytes, encryption, expiry and references."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        report = sample_store.status(
            ttl=ttl_seconds,
            results_roots=[results_root] if results_root else None,
            queue_db=_resolved_queue_db(queue_db),
        )
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
        return
    key = report["key"]
    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Sample store\n"
            f"Root:      [cyan]{report['store_root']}[/cyan]\n"
            f"Index:     [cyan]{report['index']}[/cyan]\n"
            f"Samples:   [cyan]{report['samples']}[/cyan] "
            f"({report['encrypted']} encrypted, {report['legacy_plaintext']} legacy plaintext)\n"
            f"Bytes:     [cyan]{_human_size(report['bytes'])}[/cyan]\n"
            f"References: {report['referenced']} referenced · "
            f"{report['references']['bundles_scanned']} bundle(s), "
            f"{report['references']['jobs_scanned']} queued/running job(s) scanned\n"
            f"Retention: "
            + (f"[cyan]{report['ttl_seconds']:.0f}s[/cyan]" if report["ttl_enabled"] else "[dim]disabled[/dim]")
            + f" · expired {report['expired']} · reclaimable {report['reclaimable']} "
            f"({_human_size(report['reclaimable_bytes'])})",
            title="Store",
        )
    )
    if key.get("configured"):
        console.print(f"  Key: [cyan]{key['key_id']}[/cyan] from {key['source']}")
        counts = key.get("per_key_blob_counts") or {}
        if counts:
            rendered = ", ".join(f"{name}×{count}" for name, count in sorted(counts.items()))
            console.print(f"  Keys: {len(key.get('key_ids') or [])} in ring · blobs per key: {rendered}")
        if key.get("retired_key_ids"):
            console.print(
                f"  Retired keys: {', '.join(key['retired_key_ids'])} "
                "[dim](kept for reading; retire one only when no blob needs it)[/dim]"
            )
        if key.get("rotation_complete") is False:
            console.print(
                f"  [yellow]rotation incomplete[/yellow] — "
                f"{key.get('rotation_pending', 0)} blob(s) still on a retired key; "
                "run `hatchery store key rotate` (it resumes)"
            )
        else:
            console.print("  Rotation: [green]complete[/green] (no blob needs a retired key)")
        if key.get("warning"):
            console.print(f"  [yellow]{key['warning']}[/yellow]")
    else:
        console.print(f"  Key: [yellow]not configured[/yellow] — {key.get('note', '')}")
    for warning in report.get("warnings") or []:
        console.print(f"  [yellow]warning:[/yellow] {warning}")
    for line in (report.get("references") or {}).get("unreadable_jobs") or []:
        console.print(f"  [red]unreadable job reference:[/red] {line}")
    console.print("  [dim]No sample is modified by status.[/dim]")


@store.command("verify")
@_store_common_options
@click.option("--sha", "sha256", default=None, help="Verify one content address instead of every sample")
def store_verify(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, sha256: Optional[str],
) -> None:
    """Decrypt and hash-check stored samples; fail closed on any mismatch."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        report = sample_store.verify(sha256=sha256)
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        for entry in report["entries"]:
            status = entry.get("status")
            color = {"ok": "green", "legacy": "yellow"}.get(str(status), "red")
            console.print(
                f"  [{color}]{status:<7}[/{color}] {entry['sha256'][:16]} "
                f"{entry.get('encryption', '')}"
                + (f" — {entry.get('reason', '')}: {entry.get('message', '')}" if entry.get("message") else "")
            )
        console.print(
            f"verify: {report['checked']} checked, {report['passed']} passed, "
            f"{report['failed']} failed, {report['legacy']} legacy plaintext"
        )
        ring = (report.get("key") or {})
        if ring.get("configured") and ring.get("rotation_complete") is False:
            console.print(
                f"  [yellow]rotation incomplete[/yellow] — "
                f"{ring.get('rotation_pending', 0)} blob(s) still on a retired key"
            )
    if not report["ok"]:
        raise SystemExit(STORE_EXIT_FAILURES)


@store.command("migrate")
@_store_common_options
@click.option("--dry-run", is_flag=True, help="Report what would be encrypted without writing")
@click.option("--adopt-queue/--no-adopt-queue", "adopt_queue", default=True,
              help="Also adopt pre-D28 queued jobs into the store (default: on)")
def store_migrate(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, dry_run: bool, adopt_queue: bool,
) -> None:
    """Encrypt a legacy plaintext store, idempotently and resumably."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        queue_path = _resolved_queue_db(queue_db) if adopt_queue else None
        report = sample_store.migrate(apply=not dry_run, queue_db=queue_path)
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    failures = report.get("failed") or []
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        if dry_run:
            console.print(
                f"migrate (dry run): {report['legacy_found']} legacy plaintext "
                f"sample(s) would be encrypted"
            )
            for sha in report["would_encrypt"]:
                console.print(f"  would encrypt {sha[:16]}")
        else:
            console.print(
                f"migrate: encrypted {len(report['encrypted'])} of "
                f"{report['legacy_found']} legacy plaintext sample(s)"
            )
            for item in report["encrypted"]:
                console.print(f"  [green]encrypted[/green] {item['sha256'][:16]}")
        for item in report.get("adopted_queue_jobs") or []:
            console.print(
                f"  [green]adopted[/green] queued job {item['job_id']} -> {item['sha256'][:16]}"
            )
        for item in failures:
            what = item.get("job_id") or item.get("sha256", "?")[:16]
            console.print(
                f"  [red]failed[/red] {what}: {item.get('reason')}: {item.get('message')}"
            )
        if report.get("key_notice"):
            console.print(f"  [yellow]{report['key_notice']}[/yellow]")
    if failures:
        raise SystemExit(STORE_EXIT_FAILURES)


@store.command("prune")
@_store_common_options
@click.option("--apply", is_flag=True, help="Delete; without it prune is a dry run")
@click.option("--ttl", "ttl_seconds", type=float, default=None,
              help="Retention TTL in seconds (0 disables; default: HATCHERY_SAMPLE_TTL)")
def store_prune(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, apply: bool,
    ttl_seconds: Optional[float],
) -> None:
    """Delete expired samples that no bundle or job still references."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        report = sample_store.prune(
            ttl=ttl_seconds,
            apply=apply,
            results_roots=[results_root] if results_root else None,
            queue_db=_resolved_queue_db(queue_db),
        )
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    summary = report.get("summary") or {}
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        mode = "apply" if report["applied"] else "dry run (pass --apply to delete)"
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Prune ({mode})\n"
                f"Root: [cyan]{report['store_root']}[/cyan]\n"
                + ("TTL: [cyan]{:.0f}s[/cyan]".format(report["ttl_seconds"]) if report["ttl_enabled"] else "TTL: [dim]disabled[/dim]")
                + f" · kept {summary.get('kept', 0)} · would delete "
                f"{summary.get('would_delete', 0)} · deleted {summary.get('deleted', 0)}",
                title="Prune",
            )
        )
        for entry in report.get("deleted") or []:
            console.print(f"  [red]deleted[/red] {entry['sha256'][:16]} ({entry.get('reason')})")
        for entry in report.get("would_delete") or []:
            console.print(
                f"  [yellow]would delete[/yellow] {entry['sha256'][:16]} "
                f"({entry.get('reason')}, age {entry.get('age_seconds', 0):.0f}s)"
            )
        for entry in report.get("kept") or []:
            why = entry.get("reason")
            refs = ", ".join(entry.get("referenced_by") or [])
            console.print(
                f"  [dim]kept[/dim] {entry['sha256'][:16]} ({why}"
                + (f": {refs}" if refs else "") + ")"
            )
        for refusal in report.get("refused") or []:
            console.print(f"  [red]refused:[/red] {refusal}")
        for error in report.get("errors") or []:
            console.print(f"  [red]error:[/red] {error}")
    if report.get("refused") or report.get("errors"):
        raise SystemExit(STORE_EXIT_FAILURES)


@store.command("keygen")
@click.option("--output", "-o", "output", type=click.Path(path_type=Path), required=True,
              help="Path for the new key file (created 0600, never overwritten)")
def store_keygen(output: Path) -> None:
    """Generate a 32-byte key file (0600). The key is never printed."""
    from engine.store import SampleStoreError, generate_key

    _logs_to_stderr()
    try:
        key = generate_key(output)
    except SampleStoreError as exc:
        _store_command_failed(exc, False)
        return
    click.echo(
        json.dumps({"path": str(output), "key_id": key.key_id, "mode": "0600"})
    )


# ---------------------------------------------------------------------------
# hatchery store key — key ring, rotation and retirement (D29)
# ---------------------------------------------------------------------------


@store.group("key")
def store_key() -> None:
    """Key ring: active key, retired keys, per-blob resolution and rotation.

    The envelope names its key id; decryption resolves that key by id, never by
    trying keys until one works. `status` reports the ring and whether rotation
    is complete, `rotate` re-wraps every blob onto a new active key (idempotent,
    resumable and atomic per blob), and `retire` removes a retired key only when
    no blob still needs it. No command prints key material.
    """


@store_key.command("status")
@_store_common_options
def store_key_status(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool,
) -> None:
    """Show the active key id, retired keys and per-key blob counts."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        report = {
            "store_root": str(sample_store.root),
            "key": sample_store.key_status(),
            "rotation": sample_store.rotation_state(),
        }
    except SampleStoreError as exc:
        _store_command_failed(exc, as_json)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
        return
    key = report["key"]
    rotation = report["rotation"]
    if not key.get("configured"):
        console.print(f"[yellow]No key configured.[/yellow] {key.get('note', '')}")
        return
    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Sample-store key ring\n"
            f"Active:  [cyan]{key['active_key_id']}[/cyan] from {key['source']}\n"
            f"Keys:    {len(key.get('key_ids') or [])} in ring"
            + (f" · retired {', '.join(key['retired_key_ids'])}" if key.get("retired_key_ids") else "")
            + "\n"
            f"Blobs:   {rotation['blobs']} total · "
            + (", ".join(f"{name}×{count}" for name, count in sorted(rotation['per_key_blob_counts'].items())) or "none")
            + "\n"
            "Rotation: "
            + ("[green]complete[/green]" if rotation["rotation_complete"] else f"[yellow]incomplete[/yellow] ({rotation['rotation_pending']} pending)")
            + (" · [yellow]in progress[/yellow]" if rotation.get("rotation_in_progress") else ""),
            title="Key ring",
        )
    )
    if key.get("warning"):
        console.print(f"  [yellow]{key['warning']}[/yellow]")


@store_key.command("rotate")
@_store_common_options
@click.option("--dry-run", is_flag=True, help="Report what would be re-wrapped without writing")
@click.option("--key-file", "key_file", type=click.Path(path_type=Path), default=None,
              help="Use this 0600 key file as the new active key (default: generate one)")
def store_key_rotate(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, dry_run: bool,
    key_file: Optional[Path],
) -> None:
    """Re-wrap every blob onto a new active key, atomically and resumably."""
    from engine.store import SampleStoreError, load_key_file

    sample_store = None
    try:
        new_key = load_key_file(key_file) if key_file is not None else None
        sample_store = _open_store(store_root)
        report = sample_store.rotate_key(new_key=new_key, dry_run=dry_run)
    except SampleStoreError as exc:
        code = STORE_EXIT_FAILURES if getattr(exc, "reason", "") in {
            "unknown-key-id", "rotation-incomplete", "no-key",
        } else STORE_EXIT_ERROR
        _store_command_failed(exc, as_json, code)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        mode = "dry run" if dry_run else report.get("mode", "rotate")
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Key rotation ({mode})\n"
                f"Active:  {report.get('active_before') or '(none)'} → "
                f"[cyan]{report.get('new_key_id') or report.get('active_after') or '(would generate)'}[/cyan]\n"
                f"Blobs:   {len(report.get('rotated') or [])} re-wrapped · "
                f"{len(report.get('already_active') or [])} already active · "
                f"{len(report.get('would_rotate') or [])} would rotate · "
                f"{len(report.get('failed') or [])} failed",
                title="Rotate",
            )
        )
        for item in report.get("failed") or []:
            console.print(
                f"  [red]failed[/red] {item.get('sha256', '?')[:16]} "
                f"({item.get('reason')}: {item.get('message')})"
            )
        if not dry_run:
            if report.get("complete"):
                console.print("  [green]Rotation complete[/green] — no blob references a retired key.")
            else:
                console.print(
                    "  [yellow]Rotation incomplete[/yellow] — some blobs were left untouched. "
                    "Run the command again to resume; nothing was deleted."
                )
    if dry_run:
        if report.get("failed"):
            raise SystemExit(STORE_EXIT_FAILURES)
        return
    if report.get("failed") or not report.get("complete"):
        raise SystemExit(STORE_EXIT_FAILURES)


@store_key.command("retire")
@_store_common_options
@click.argument("key_id")
def store_key_retire(
    store_root: Optional[Path], results_root: Optional[Path],
    queue_db: Optional[Path], as_json: bool, key_id: str,
) -> None:
    """Remove a retired key from the ring; refused while any blob needs it."""
    from engine.store import SampleStoreError

    sample_store = None
    try:
        sample_store = _open_store(store_root)
        report = sample_store.retire_key(key_id)
    except SampleStoreError as exc:
        code = STORE_EXIT_FAILURES if exc.reason in {
            "key-in-use", "key-not-found", "rotation-incomplete",
        } else STORE_EXIT_ERROR
        _store_command_failed(exc, as_json, code)
        return
    finally:
        if sample_store is not None:
            sample_store.close()
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        console.print(
            f"[green]Retired key {report['retired']}[/green]. Active: "
            f"[cyan]{report['active_key_id']}[/cyan] · ring: "
            f"{', '.join(report['key_ids'])}"
        )


# ---------------------------------------------------------------------------
# hatchery store backup / restore (D29)
# ---------------------------------------------------------------------------


@store.command("backup")
@click.option("--output", "-o", "output", type=click.Path(path_type=Path), required=True,
              help="Directory for the backup (manifest is written last)")
@click.option("--include-key", is_flag=True,
              help="Include the key ring (a secret) inside the backup; loudly warned")
@click.option("--queue", "queue_db", type=click.Path(path_type=Path), default=None,
              help="Queue database to include (default: data/queue.db or HATCHERY_QUEUE_DB)")
@click.option("--store", "store_root", type=click.Path(path_type=Path), default=None,
              help="Sample store root (default: HATCHERY_SAMPLE_STORE or <checkout>/samples)")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def store_backup(
    output: Path, include_key: bool, queue_db: Optional[Path],
    store_root: Optional[Path], as_json: bool,
) -> None:
    """Write a self-describing backup of the store (blobs + index) and the queue.

    Live SQLite databases are copied with SQLite's backup API (never a file copy
    of a WAL database), every blob is hashed as it is copied, and the manifest is
    written last — an interrupted backup has no manifest. The key is excluded by
    default; --include-key writes it 0600 inside the backup and says so loudly.
    Exit codes: 0 success, 1 operational error, 2 a store state that cannot be
    backed up safely (legacy plaintext, newer schema).
    """
    from engine.store import SampleStoreError, create_backup, resolve_store_root

    _logs_to_stderr()
    try:
        report = create_backup(
            resolve_store_root(store_root),
            output,
            include_key=include_key,
            queue_db=_resolved_queue_db(queue_db),
            warn=lambda message: click.echo(f"WARNING: {message}", err=True),
        )
    except SampleStoreError as exc:
        code = STORE_EXIT_FAILURES if exc.reason in {
            "backup-failed", "restore-schema-newer", "manifest-version",
        } else STORE_EXIT_ERROR
        _store_command_failed(exc, as_json, code)
        return
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
        return
    manifest = report
    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Backup\n"
            f"Output:   [cyan]{report['backup']}[/cyan]\n"
            f"Manifest: [cyan]{report['manifest']}[/cyan]\n"
            f"Samples:  [cyan]{manifest['counts']['samples']}[/cyan] "
            f"({_human_size(manifest['sizes']['blobs_bytes'])}) · "
            f"queue jobs: {manifest['counts']['queue_jobs']}\n"
            f"Key:      "
            + ("[red]INCLUDED — this backup contains a secret[/red]"
               if manifest['key']['included']
               else "[dim]not included[/dim]")
            + " · "
            + ("[green]restorable without the operator's key[/green]"
               if manifest['key']['restorable_without_operator_key']
               else "[yellow]needs the operator's key to restore[/yellow]"),
            title="Backup",
        )
    )
    if manifest["key"]["included"]:
        console.print(f"  [red]{manifest['key']['warning']}[/red]")


@store.command("restore")
@click.argument("backup", type=click.Path(path_type=Path))
@click.option("--target", "target_root", type=click.Path(path_type=Path), required=True,
              help="Empty/new restore root; the store lands in TARGET/samples")
@click.option("--force", is_flag=True,
              help="Allow a non-empty target (a blob whose bytes differ is still refused)")
@click.option("--queue", "queue_target", type=click.Path(path_type=Path), default=None,
              help="Where to restore the queue (default: TARGET/queue.db)")
@click.option("--store", "store_target", type=click.Path(path_type=Path), default=None,
              help="Where to restore the store (default: TARGET/samples)")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def store_restore(
    backup: Path, target_root: Path, force: bool, queue_target: Optional[Path],
    store_target: Optional[Path], as_json: bool,
) -> None:
    """Restore a backup into an empty/new root, failing closed.

    The backup is treated as hostile input: every path is validated, every size
    is bounds-checked, every file hash is checked against the manifest and every
    blob is authenticated against its content address before anything is
    written. A corrupt, newer or traversing backup writes nothing. A restore
    that completes with undecryptable entries exits 2 and says which key ids are
    missing — it never declares success it cannot support.
    """
    from engine.store import SampleStoreError, restore_backup

    _logs_to_stderr()
    try:
        report = restore_backup(
            backup, target_root, force=force,
            queue_target=queue_target, store_target=store_target,
        )
    except SampleStoreError as exc:
        # A refused restore writes nothing: that is an operational refusal (1).
        # A restore that completed with undecryptable entries exits 2 below.
        _store_command_failed(exc, as_json, STORE_EXIT_ERROR)
        return
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Restore\n"
                f"Backup: [cyan]{report['backup']}[/cyan]\n"
                f"Store:  [cyan]{report['store_root']}[/cyan]\n"
                f"Queue:  [cyan]{report['queue_db'] or '(none in backup)'}[/cyan]\n"
                f"Samples restored: {report['samples']} · queue jobs: {report['queue_jobs']}",
                title="Restore",
            )
        )
        for item in report.get("undecryptable") or []:
            console.print(
                f"  [yellow]undecryptable[/yellow] {item['sha256'][:16]} — "
                f"{item['message']}"
            )
        for item in report.get("missing_sample_jobs") or []:
            console.print(
                f"  [red]job without its sample[/red] {item['job_id']} "
                f"({item['reason']}); it will fail with that reason, not run silently"
            )
        console.print(
            ("  [green]Restore verified.[/green]" if report["ok"]
             else f"  [red]Restore incomplete.[/red] {report['message']}")
        )
    if not report.get("ok"):
        raise SystemExit(STORE_EXIT_FAILURES)


# ---------------------------------------------------------------------------
# hatchery results — bundle integrity, retention and growth (D33)
# ---------------------------------------------------------------------------

RESULTS_EXIT_OK = 0
RESULTS_EXIT_BROKEN = 1
RESULTS_EXIT_FAILURE = 2


def _default_results_root(explicit: Optional[Path]) -> Path:
    """One results root: the explicit path, then HATCHERY_RESULTS_ROOT, then the checkout."""
    from engine.store.roots import resolve_results_roots

    if explicit is not None:
        return Path(explicit).expanduser().resolve()
    return resolve_results_roots()[0]


def _results_failed(
    reason: str, message: str, as_json: bool, code: int = RESULTS_EXIT_FAILURE
) -> NoReturn:
    if as_json:
        click.echo(json.dumps({"ok": False, "reason": reason, "message": message}), err=True)
    else:
        click.echo(f"HATCHERY results: {reason}: {message}", err=True)
    raise SystemExit(code)


def _require_verifiable_stage(run_dir: Path) -> None:
    """Refuse to mutate a run whose own bytes no longer match its manifest (D33/D34).

    A stage that re-seals is trusting the bytes it is about to change. Checking
    the incoming state first means an out-of-band edit cannot be laundered into a
    fresh manifest by a later `triage` or `push`: the operator is told the run is
    ``modified`` at a named path and must use the explicit, loud
    ``hatchery results seal --replace`` if the change was deliberate. A legacy
    run with no manifest is still allowed — an unsealed corpus must keep working.

    This checks the run's **own** file set (``_depth=1``), not its nested units:
    a nested replay is its own unit with its own manifest, and this stage neither
    rewrites nor repairs it. A nested ``unsealed``/``broken`` state is reported by
    ``results verify`` and fixed by ``results seal --all``; it must not turn a
    legitimate triage of an otherwise intact run into a refusal.
    """
    from engine.results import resolve_run_root, verify_run

    try:
        root = resolve_run_root(run_dir)
    except Exception:  # noqa: BLE001 - a path that is not a run is reported by the stage
        return
    report = verify_run(root, _depth=1)
    if report["state"] != "broken":
        return
    console.print(
        f"[red]Refusing to modify {root}: the run is {report['classification']} at "
        f"{report['path']}.[/red]\n"
        "[yellow]The bundle no longer matches its manifest. If the change was "
        "deliberate, re-seal it explicitly with:\n"
        f"  hatchery results seal {root} --replace[/yellow]"
    )
    raise SystemExit(1)


def _reseal_after_stage(run_dir: Path, stage: str) -> None:
    """Write the run's manifest after a stage that mutated it (D4/D33).

    One writer, one call site per stage. A manifest written only at submit time
    would report ``modified`` after a legitimate triage; a stage that cannot
    re-seal exits non-zero rather than leaving a stale manifest that claims the
    run is unchanged when it is not.
    """
    from engine.results import ManifestError, resolve_run_root, seal_run as seal_result_run

    try:
        manifest = seal_result_run(resolve_run_root(run_dir), stage=stage)
    except ManifestError as exc:
        console.print(
            f"[red]The run was modified but cannot be re-sealed: {exc.reason}: "
            f"{exc.message}[/red]\n[red]`hatchery results verify` will report it as "
            "modified/missing until it is sealed.[/red]"
        )
        raise SystemExit(1) from exc
    console.print(
        f"  Manifest re-sealed at stage [cyan]{stage}[/cyan]: "
        f"[cyan]{manifest['manifest_sha256']}[/cyan]"
    )


@cli.group()
def results() -> None:
    """Result bundles: seal, verify, retention and growth (D33).

    A run directory (``results/<run>/``) is the artifact an analyst hands to a
    client. ``manifest.json`` at the run root hashes every file and is written
    last by every stage that touches the run; ``verify`` recomputes those hashes
    and names the first break.

    The manifest proves the run directory has not changed since the last
    HATCHERY stage that touched it — not "since submit", and not "unmodified
    since delivery". It is a hash manifest, not a signature: record its sha256
    when you deliver the run and pass it to ``verify --expect-manifest`` to
    catch a rewrite of an artifact together with its manifest.

    Retention is off by default and applied only by ``results prune --apply``;
    ``results status`` reports growth and never deletes. Every subcommand takes
    ``--json``: one object on stdout, diagnostics on stderr. Exit codes: 0
    intact (or unsealed without an anchor), 1 broken or refused, 2 usage.
    """


@results.command("verify")
@click.argument("run", type=click.Path(path_type=Path))
@click.option(
    "--expect-manifest", "expect_manifest", default=None,
    help="The manifest sha256 recorded when the run was delivered (the anchor)",
)
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def results_verify(run: Path, expect_manifest: Optional[str], as_json: bool) -> None:
    """Recompute every hash in a run and name the first break.

    Works on a copied run directory (the manifest is relocatable) and on a run
    with no database. A legacy run with no manifest reports ``unsealed`` — never
    ``ok`` — and exits 0 so an existing corpus keeps working; pass
    ``--expect-manifest`` to make a missing manifest a failure.

    A run directory's conclusion includes its nested units: a nested replay with
    no manifest is ``nested-unsealed``, ``ok`` false and exit 1, because the
    directory ships evidence HATCHERY cannot verify (D34).
    """
    from engine.results import ManifestError, resolve_run_root, verify_run

    _logs_to_stderr()
    try:
        run_root = resolve_run_root(run)
    except ManifestError as exc:
        _results_failed(exc.reason, exc.message, as_json, RESULTS_EXIT_FAILURE)
        return
    report = verify_run(run_root, expect_manifest=expect_manifest)
    # The relative path of a break is what an operator can act on; the run id is
    # reported but never compared to the directory name.
    report["run"] = str(run)
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        state = report["state"]
        color = {"intact": "green", "unsealed": "yellow", "broken": "red"}[state]
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Result bundle\n"
                f"Run:    [cyan]{run_root}[/cyan]\n"
                f"State:  [{color}]{state}[/{color}]"
                + (f"\nBreak:  [red]{report['classification']} at {report['path']}[/red]" if report["classification"] else "")
                + (f"\nAnchor: [red]{report['anchor']['expected']} != {report['anchor']['actual']}[/red]" if report.get("anchor") and not report["anchor"]["match"] else "")
                + f"\nStage:  {report['stage'] or '(none)'} · sealed {report['sealed_at'] or '(never)'}",
                title="Verify",
            )
        )
        if report["manifest_sha256"]:
            console.print(f"  manifest.json: [cyan]{report['manifest_sha256']}[/cyan]")
        if report["state"] != "unsealed":
            console.print(
                f"  Files: {report['file_count']} ([cyan]{report['hashed']}[/cyan] hashed) · "
                f"bytes: {report['total_bytes']} · manifest v{report['manifest_version']}"
            )
        if report.get("anchor"):
            mark = "[green]matches the anchor[/green]" if report["anchor"]["match"] else "[red]does NOT match the anchor[/red]"
            console.print(f"  Anchor: {mark} ({report['anchor']['actual']})")
        for nested in report.get("nested_runs") or []:
            if nested["state"] == "unsealed":
                console.print(
                    f"  [bold red]⚠ nested replay {nested['run_id']}: unsealed[/bold red] "
                    "— no manifest; HATCHERY cannot verify evidence this directory ships"
                )
                continue
            mark = {"intact": "[green]intact[/green]", "broken": "[red]broken[/red]"}[
                nested["state"]
            ]
            console.print(f"  nested replay {nested['run_id']}: {mark}")
        if report.get("stale_temporaries"):
            console.print(
                "  [yellow]stale seal temporaries (not part of the bundle):[/yellow] "
                + ", ".join(report["stale_temporaries"])
            )
        if report.get("error"):
            console.print(f"  [yellow]{report['error']}[/yellow]")
        if report.get("anchor") and report["anchor"].get("match") and report["state"] == "broken":
            console.print(
                "  [yellow]The anchor matches, so this is the parent manifest you "
                "recorded — but the directory is still broken. The anchor proves "
                "the parent manifest, not that every nested unit inside this "
                "directory is verifiable.[/yellow]"
            )
    if report["state"] == "intact":
        raise SystemExit(RESULTS_EXIT_OK)
    if report["state"] == "unsealed":
        raise SystemExit(RESULTS_EXIT_OK)
    raise SystemExit(RESULTS_EXIT_BROKEN)


@results.command("seal")
@click.argument("run", type=click.Path(path_type=Path))
@click.option("--replace", is_flag=True, help="Re-seal a run whose existing manifest does not match")
@click.option(
    "--all", "all_runs", is_flag=True,
    help="Seal every run under RUN (a results root), nested units first (D34)",
)
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def results_seal(run: Path, replace: bool, all_runs: bool, as_json: bool) -> None:
    """Seal a run written before the manifest existed — or a whole corpus.

    For one run: idempotent. A valid existing manifest is returned unchanged
    (its hash printed) and nothing is rewritten. Refuses when an existing
    manifest does not match the run. ``--replace`` re-seals anyway, prints the
    old hash and states that any anchor to it is void.

    With ``--all``, RUN is a results root: every run under it is sealed
    depth-first (a nested replay before its parent), so a legacy corpus becomes
    verifiable in one command. Sealing a nested unit never rewrites the parent's
    manifest, so a parent anchor recorded at delivery stays valid. Each unit is
    reported as ``sealed`` or ``already`` (with its manifest sha256) or
    ``refused`` (with reason, classification and path); hidden entries,
    ``.deleting-*`` strays, symlinks and non-run directories are ``ignored``.
    Exit 0 when nothing was refused, 2 when a run was refused, 1 on an
    operational error. ``--replace`` is refused with ``--all``: re-sealing
    mismatches across a corpus would bless tamper everywhere it is found.
    """
    from engine.results import ManifestError, ensure_sealed, seal_corpus

    _logs_to_stderr()
    if all_runs:
        if replace:
            _results_failed(
                "replace-not-allowed",
                "--replace cannot be used with --all: re-sealing a mismatch across a "
                "whole corpus would bless tamper wherever it is found. Seal the one "
                "run deliberately, then re-run --all.",
                as_json,
                RESULTS_EXIT_FAILURE,
            )
            return
        try:
            report = seal_corpus(run)
        except ManifestError as exc:
            _results_failed(exc.reason, exc.message, as_json, RESULTS_EXIT_BROKEN)
            return
        if as_json:
            click.echo(json.dumps(report, indent=2, default=str))
        else:
            counts = report["counts"]
            console.print(
                Panel(
                    f"[bold orange_red1]HATCHERY[/bold orange_red1] — Seal corpus\n"
                    f"Root:    [cyan]{report['results_root']}[/cyan]\n"
                    f"Sealed:  {counts['sealed']} · already {counts['already']} · "
                    f"refused {counts['refused']} · ignored {counts['ignored']}",
                    title="Seal --all",
                )
            )
            for entry in report["sealed"]:
                console.print(
                    f"  [green]sealed[/green] [cyan]{entry['run_id']}[/cyan] "
                    f"(manifest {entry['manifest_sha256']})"
                )
            for entry in report["already"]:
                console.print(
                    f"  [dim]already[/dim] [cyan]{entry['run_id']}[/cyan] "
                    f"(manifest {entry['manifest_sha256']})"
                )
            for entry in report["refused"]:
                console.print(
                    f"  [red]refused[/red] [cyan]{entry['run_id']}[/cyan]: "
                    f"{entry['reason']}"
                    + (
                        f" ({entry['classification']} at {entry['break_path']})"
                        if entry.get("classification")
                        else ""
                    )
                    + f" — {entry['message']}"
                )
            for entry in report["ignored"]:
                console.print(
                    f"  [dim]ignored[/dim] {entry['name']} ({entry['reason']})"
                )
            console.print(
                "  Record each manifest sha256 when you deliver the run; sealing a "
                "nested unit never changes its parent's hash."
            )
        if report["refused"]:
            raise SystemExit(RESULTS_EXIT_FAILURE)
        raise SystemExit(RESULTS_EXIT_OK)
    try:
        report = ensure_sealed(run, replace=replace)
    except ManifestError as exc:
        _results_failed(exc.reason, exc.message, as_json, RESULTS_EXIT_FAILURE)
        return
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        previous = report.get("previous_manifest_sha256")
        if previous:
            console.print(
                f"[yellow]⚠ Replaced the existing manifest. The previous hash was\n"
                f"  {previous}\n"
                "  Any anchor recorded against it is void.[/yellow]"
            )
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Seal\n"
                f"Run:     [cyan]{report['run_dir']}[/cyan]\n"
                f"Stage:   {report['stage']} · sealed {report['sealed_at']}\n"
                f"Files:   {report['file_count']} ({report['total_bytes']} bytes)"
                + ("" if report["written"] else "\n[dim]Already sealed and intact — nothing rewritten.[/dim]"),
                title="Seal",
            )
        )
        console.print(f"  manifest sha256: [cyan]{report['manifest_sha256']}[/cyan]")
        console.print(
            "  Record this hash when you deliver the run, then check it with "
            "`hatchery results verify <run> --expect-manifest <sha256>`."
        )
    raise SystemExit(RESULTS_EXIT_OK)


@results.command("prune")
@click.option(
    "--older-than", "older_than", default=None,
    help="Delete runs sealed more than this long ago (30d, 12h, 3600s; else HATCHERY_RESULTS_RETENTION_DAYS)",
)
@click.option(
    "--keep-last", "keep_last", type=int, default=None,
    help="Always keep the newest N runs (default 1, minimum 1; else HATCHERY_RESULTS_KEEP_LAST)",
)
@click.option("--apply", is_flag=True, help="Actually delete; the default is a dry run")
@click.option("--results", "results_root", type=click.Path(path_type=Path), default=None,
              help="Results root (default: HATCHERY_RESULTS_ROOT, then <checkout>/results)")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def results_prune(
    older_than: Optional[str], keep_last: Optional[int], apply: bool,
    results_root: Optional[Path], as_json: bool,
) -> None:
    """Delete verified, expired runs — dry run unless --apply.

    Retention is off by default (no --older-than and no retention environment
    variable means nothing expires) and nothing in submit, the worker or the API
    calls this. A run with no manifest, an invalid manifest or an unparseable
    bundle is never deleted: --apply refuses the whole plan and exits non-zero.
    Deletion renames the run to ``<run>.deleting-<ts>`` before removing it, so a
    crash leaves a stray the next prune completes.
    """
    from engine.results import RetentionError, prune_runs, resolve_policy

    _logs_to_stderr()
    root = _default_results_root(results_root)
    try:
        policy = resolve_policy(older_than=older_than, keep_last=keep_last)
        report = prune_runs(root, policy=policy, apply=apply)
    except RetentionError as exc:
        _results_failed(exc.reason, exc.message, as_json, RESULTS_EXIT_FAILURE)
        return
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
    else:
        mode = "apply" if report["applied"] else "dry run (pass --apply to delete)"
        policy_text = (
            f"older than {report['policy']['older_than']}" if report["policy"]["older_than"]
            else "no expiry"
        )
        console.print(
            Panel(
                f"[bold orange_red1]HATCHERY[/bold orange_red1] — Results prune ({mode})\n"
                f"Root:   [cyan]{report['results_root']}[/cyan]\n"
                f"Policy: {policy_text} · keep newest {report['policy']['keep_last']}"
                + (" [yellow](clamped)[/yellow]" if report["clamped"] else "")
                + f"\nRuns:   {report.get('runs', 0)} · delete "
                f"{report['summary']['delete']} · keep {report['summary']['keep']}",
                title="Prune",
            )
        )
        for item in report.get("decisions") or []:
            color = "red" if item["decision"] == "delete" else "dim"
            nested = f", {item['nested_runs']} nested replay(s)" if item.get("nested_runs") else ""
            console.print(
                f"  [{color}]{item['decision']}[/{color}] [cyan]{item['run_id']}[/cyan] "
                f"({item['reason']}, {item['bytes']} bytes{nested})"
            )
        for stray in report.get("strays") or []:
            console.print(f"  [yellow]stray[/yellow] {stray['name']} ({stray['bytes']} bytes)")
        for resumed in report.get("resumed_strays") or []:
            console.print(f"  [red]resumed[/red] {resumed}")
        for refused in report.get("refused") or []:
            console.print(f"  [red]refused[/red] {refused['run_id']}: {refused['message']}")
        if report.get("blocked"):
            console.print(
                "  [bold red]Plan blocked — nothing will be deleted.[/bold red] "
                "Seal the corpus first: hatchery results seal <results-root> --all"
            )
        for error in report.get("errors") or []:
            console.print(f"  [red]error[/red] {error}")
        console.print(
            f"  bytes freed: {report.get('bytes_freed', 0)} · prune log: "
            f"[cyan]{(report.get('prune_log') or {}).get('path')}[/cyan]"
        )
    if report.get("locked"):
        raise SystemExit(RESULTS_EXIT_FAILURE)
    if report.get("refused") or report.get("errors"):
        raise SystemExit(RESULTS_EXIT_FAILURE)
    raise SystemExit(RESULTS_EXIT_OK)


@results.command("status")
@click.option(
    "--older-than", "older_than", default=None,
    help="Preview a prune policy (else HATCHERY_RESULTS_RETENTION_DAYS)",
)
@click.option("--keep-last", "keep_last", type=int, default=None, help="Preview the anchor size")
@click.option("--results", "results_root", type=click.Path(path_type=Path), default=None,
              help="Results root (default: HATCHERY_RESULTS_ROOT, then <checkout>/results)")
@click.option("--json", "as_json", is_flag=True, help="Emit one JSON object on stdout")
def results_status(
    older_than: Optional[str], keep_last: Optional[int],
    results_root: Optional[Path], as_json: bool,
) -> None:
    """Run count, bytes, oldest/newest, strays, growth — never deletes."""
    from engine.results import RetentionError, resolve_policy, status_report

    _logs_to_stderr()
    root = _default_results_root(results_root)
    try:
        policy = resolve_policy(older_than=older_than, keep_last=keep_last)
        report = status_report(root, policy=policy)
    except RetentionError as exc:
        _results_failed(exc.reason, exc.message, as_json, RESULTS_EXIT_FAILURE)
        return
    if as_json:
        click.echo(json.dumps(report, indent=2, default=str))
        raise SystemExit(RESULTS_EXIT_OK)
    growth = report["growth"]
    console.print(
        Panel(
            f"[bold orange_red1]HATCHERY[/bold orange_red1] — Result bundles\n"
            f"Root:  [cyan]{report['results_root']}[/cyan]\n"
            f"Runs:  {report['runs']} ({report['bytes']} bytes) · "
            f"nested replays: {report['nested_replay_runs']}\n"
            f"Oldest: {report['oldest']['run_id'] if report['oldest'] else '(none)'} "
            f"{report['oldest']['sealed_at'] if report['oldest'] else ''}\n"
            f"Newest: {report['newest']['run_id'] if report['newest'] else '(none)'} "
            f"{report['newest']['sealed_at'] if report['newest'] else ''}",
            title="Results",
        )
    )
    warn = " [red](threshold-crossed)[/red]" if growth["warned"] else ""
    console.print(
        f"  Growth: {growth['runs']}/{growth['warn_runs']} runs · "
        f"{growth['bytes']}/{growth['warn_bytes']} bytes · enforced: {growth['enforced']}{warn}"
    )
    console.print(
        "  A prune would remove: "
        + (", ".join(report["would_remove"]) if report["would_remove"] else "nothing")
        + f" ({report['would_free_bytes']} bytes, keep newest {report['policy']['keep_last']})"
    )
    if report.get("unsealed_runs") or report.get("unsealed_nested"):
        console.print(
            f"  Unsealed: [yellow]{report['unsealed_runs']}[/yellow] run(s), "
            f"[yellow]{report['unsealed_nested']}[/yellow] nested unit(s) — "
            "a prune --apply would be refused until they are sealed"
        )
    for stray in report.get("strays") or []:
        console.print(f"  [yellow]stray[/yellow] {stray['name']} ({stray['bytes']} bytes)")
    for refused in report.get("refused") or []:
        console.print(
            f"  [red]{refused['reason']}[/red] {refused['run_id']}: {refused['message']}"
        )
    if report.get("blocked"):
        console.print(
            "  [bold red]A prune --apply would refuse the whole plan and delete "
            "nothing.[/bold red] Seal the corpus first: "
            "hatchery results seal <results-root> --all"
        )
    if report.get("ignored"):
        console.print(f"  [dim]ignored (not runs): {', '.join(report['ignored'])}[/dim]")
    log = report.get("prune_log") or {}
    console.print(f"  Prune log: [cyan]{log.get('path')}[/cyan] ({log.get('entries', 0)} entries)")
    raise SystemExit(RESULTS_EXIT_OK)


@cli.command()
@click.option(
    "--root",
    type=click.Path(path_type=Path),
    default=Path("results"),
    help="Default results root for the read-only tools",
)
def mcp(root: Path) -> None:
    """Run the MCP server on stdio, so an agent can call HATCHERY as a tool.

    Exposes submit_sample, list_runs, get_report, get_iocs, triage_run and
    cluster_runs over newline-delimited JSON-RPC 2.0. stdout is the protocol
    channel: nothing else is printed to it. Local stdio only — never expose it
    on a socket.
    """
    from engine.mcp.server import MCPServer

    MCPServer(results_root=root).serve(sys.stdin, sys.stdout)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@internal_error_backstop
def static(file: Path) -> None:
    """Run static analysis only (no sandbox execution)."""
    # D40: this command writes nothing and never touches the sample store, so it
    # applies the same sample rule itself — on the stat, before the string
    # extractor reads the file. `submit` gets the same refusal from the store's
    # intake path (`put_file`).
    from engine.store import DEFAULT_MAX_SAMPLE_BYTES
    from engine.store.limits import SampleSourceError, check_sample_source

    try:
        check_sample_source(file, limit=DEFAULT_MAX_SAMPLE_BYTES)
    except SampleSourceError as exc:
        console.print(
            f"[red]Cannot analyse the sample: {exc.reason}: {exc.message}[/red]"
        )
        raise SystemExit(1) from exc

    # Delegate to submit with --no-sandbox
    console.print("[dim]Running static analysis only (no sandbox)[/dim]")
    # We invoke the submit logic directly
    from engine.intake.hasher import MultiHasher
    from engine.intake.strings import StringExtractor
    from engine.static.yara_scanner import YARAScanner
    from engine.static.capa_scanner import CapaScanner
    from engine.static.packer_detect import PackerDetector

    console.print(f"\n[bold]Static Analysis: {file.name}[/bold]\n")

    # Same delivery-intake path as `submit`: a container's contents are opened
    # before the static stages, so a document is never an empty result. This
    # command writes nothing, so the extraction lands in a temporary directory.
    import tempfile
    from engine.intake.delivery import DeliveryFormat

    delivery_result, _ = _run_delivery_intake(
        file, Path(tempfile.mkdtemp(prefix="hatchery-delivery-"))
    )
    if delivery_result.format is not DeliveryFormat.UNKNOWN:
        _print_delivery(delivery_result)

    # Hashes
    hasher = MultiHasher()
    hash_result = hasher.hash_file(file)
    _print_hashes(hash_result.to_dict())

    # D39: the same funnel `submit` uses. `static` reads the same hostile bytes
    # and must not answer a parser bug with a traceback either.
    from engine.guard import guarded
    from engine.intake.strings import StringClassification

    stage_errors: list[str] = []
    string_extractor = StringExtractor()
    strings = guarded(
        "string extraction",
        stage_errors,
        lambda: string_extractor.extract(file),
        fallback_factory=StringClassification,
    )
    assert strings is not None, "the fallback above is never None"
    console.print(f"\n[bold]Strings:[/bold] {len(strings.all_strings)} total")
    if strings.urls:
        console.print(f"  [red]URLs ({len(strings.urls)}):[/red]")
        for url in strings.urls[:10]:
            console.print(f"    {url}")
    if strings.ips:
        console.print(f"  [red]IPs ({len(strings.ips)}):[/red]")
        for ip in strings.ips[:10]:
            console.print(f"    {ip}")
    if strings.domains:
        console.print(f"  [red]Domains ({len(strings.domains)}):[/red]")
        for domain in strings.domains[:10]:
            console.print(f"    {domain}")

    # YARA
    console.print("\n[bold]YARA Scan[/bold]")
    from engine.static.yara_scanner import YARAResult

    yara_scanner = YARAScanner()
    yara_result = guarded(
        "YARA scan",
        stage_errors,
        lambda: yara_scanner.scan(file),
        fallback_factory=lambda: YARAResult(
            rules_loaded=0, error="scan failed unexpectedly; see the stage error above"
        ),
    )
    assert yara_result is not None, "the fallback above is never None"
    _print_yara_results(yara_result.to_dict())

    # capa
    console.print("\n[bold]capa Analysis[/bold]")
    from engine.static.capa_scanner import CapaResult

    capa_scanner = CapaScanner()
    capa_result = guarded(
        "capa analysis",
        stage_errors,
        lambda: capa_scanner.scan(file),
        fallback_factory=lambda: CapaResult(
            error="analysis failed unexpectedly; see the stage error above"
        ),
    )
    assert capa_result is not None, "the fallback above is never None"
    _print_capa_results(capa_result.to_dict())

    # Packer
    console.print("\n[bold]Packer Detection[/bold]")
    from engine.static.packer_detect import PackerResult

    packer_detector = PackerDetector()
    packer_result = guarded(
        "packer detection",
        stage_errors,
        lambda: packer_detector.detect(file),
        fallback_factory=lambda: PackerResult(
            error="detection failed unexpectedly; see the stage error above"
        ),
    )
    assert packer_result is not None, "the fallback above is never None"
    _print_packer_results(packer_result.to_dict())
    if stage_errors:
        console.print(
            f"\n[yellow]{len(stage_errors)} stage(s) failed unexpectedly; "
            "each is named above and nothing is claimed for them.[/yellow]"
        )


@cli.command()
@click.option("--emulation", is_flag=True, help="Also build the emulation (Speakeasy) image")
def build(emulation: bool) -> None:
    """Build the sandbox Docker image (and, with --emulation, the emulator)."""
    from engine.sandbox.container import ContainerManager

    console.print("[bold]Building HATCHERY sandbox Docker image...[/bold]")
    try:
        manager = ContainerManager()
        tag = manager.build_image()
        console.print(f"[green]✓ Built sandbox image: {tag}[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]Dockerfile not found: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Build failed: {e}[/red]")
        console.print("[dim]Make sure Docker is running and you have permission[/dim]")

    if emulation:
        from engine.emulate.manager import EmulationManager

        console.print("\n[bold]Building HATCHERY emulation image...[/bold]")
        try:
            emu_tag = EmulationManager().build_image()
            console.print(f"[green]✓ Built emulation image: {emu_tag}[/green]")
        except FileNotFoundError as e:
            console.print(f"[red]Emulation Dockerfile not found: {e}[/red]")
        except Exception as e:
            console.print(f"[red]Emulation build failed: {e}[/red]")


@cli.command()
def doctor() -> None:
    """Check host readiness: isolation tier, sandbox image, and tooling.

    Answers the question that matters before you detonate anything: what
    boundary is actually in force on this machine, and what is missing.
    """
    from engine.sandbox.container import ContainerConfig, ContainerManager
    from engine.sandbox.isolation import describe_tiers

    console.print(Panel("Host readiness", title="\U0001fa7a HATCHERY Doctor"))
    console.print(describe_tiers())
    console.print()

    manager = ContainerManager(ContainerConfig())
    probe = manager.isolation

    if probe.errors:
        for note in probe.errors:
            console.print(f"[yellow]• {note}[/yellow]")

    if probe.selected:
        console.print(
            f"Selected: [cyan]tier {int(probe.tier)} ({probe.selected.name})[/cyan] "
            f"via runtime [cyan]{probe.runtime}[/cyan]"
        )
        if probe.selected.is_security_boundary:
            console.print(f"[green]Boundary: {probe.selected.boundary}[/green]")
        else:
            console.print(f"[red]No boundary: {probe.selected.boundary}[/red]")
        console.print(f"Monitoring: {probe.selected.monitoring}")
    else:
        console.print("[red]No isolation tier available — dynamic analysis cannot run.[/red]")

    console.print()
    ready, problems = manager.readiness()
    if ready:
        console.print("[green]Sandbox ready — detonation can run.[/green]")
    else:
        console.print("[red]Sandbox NOT ready:[/red]")
        for problem in problems:
            console.print(f"  • [red]{problem}[/red]")

    # Emulation is a separate, declared stage — never folded into the sandbox
    # readiness answer, because it rides on the same boundary but is not one.
    console.print()
    try:
        from engine.emulate.manager import EmulationContainerConfig, EmulationManager

        emu_available, emu_reason = EmulationManager(
            EmulationContainerConfig()
        ).emulation_available()
    except Exception as exc:  # noqa: BLE001
        emu_available, emu_reason = False, str(exc)
    if emu_available:
        console.print(f"Emulation: [green]available[/green] — {emu_reason}")
        console.print(
            "[dim]  Not an isolation boundary: the sample's instructions are "
            "interpreted, not executed.[/dim]"
        )
    else:
        console.print(f"Emulation: [yellow]unavailable ({emu_reason})[/yellow]")

    # Triage readiness: is a local model reachable, and which one would be used?
    # It is advisory and off by default, so an unavailable model is not a failure.
    console.print()
    try:
        from engine.triage.client import OllamaClient
        from engine.triage.client import OllamaError as _OllamaError

        triage_client = OllamaClient()
        if not triage_client.is_available():
            console.print(
                "Triage: [dim]unavailable (no local Ollama at "
                f"{triage_client.base_url})[/dim]"
            )
        else:
            selected = triage_client.resolve_model()
            console.print(f"Triage: [green]available[/green] — local model {selected}")
            console.print(
                "[dim]  Advisory only; opt in with `--triage`. Sample text stays "
                "local unless --allow-remote-model is passed.[/dim]"
            )
    except _OllamaError as exc:
        console.print(f"Triage: [dim]unavailable ({exc})[/dim]")
    except Exception as exc:  # noqa: BLE001
        console.print(f"Triage: [dim]unavailable ({type(exc).__name__})[/dim]")

    console.print()
    lint = lint_rules()
    if lint.ok:
        console.print(
            f"[green]Rules OK[/green]: {lint.files_checked} files, "
            f"{len(lint.warnings)} unaccepted warning(s)"
        )
    else:
        console.print(f"[red]Rules FAILED[/red]: {len(lint.errors)} error(s)")
        for error in lint.errors:
            console.print(f"  • [red]{error}[/red]")
    for warning in lint.warnings:
        console.print(f"  • [yellow]rule warning: {warning}[/yellow]")


@cli.group()
def rules() -> None:
    """Inspect and validate the YARA rule sets."""


@rules.command("lint")
def rules_lint() -> None:
    """Lint every YARA rule file. Exits non-zero on any error, so CI can gate on it."""
    report = lint_rules()

    console.print(
        f"Checked [cyan]{report.files_checked}[/cyan] rule file(s) in {report.rules_dir}"
    )

    for error in report.errors:
        console.print(f"[red]ERROR[/red] {error}")
    for warning in report.warnings:
        console.print(f"[yellow]WARN [/yellow] {warning}")
    for key, reason in report.accepted_warnings.items():
        console.print(f"[dim]ACCEPT {key} — {reason}[/dim]")
    for missing in report.rules_without_attack_mapping:
        console.print(f"[yellow]WARN [/yellow] {missing} has no mitre_attck mapping")

    if report.ok:
        console.print("[green]Rule lint passed[/green]")
        return

    console.print(f"[red]Rule lint failed: {len(report.errors)} error(s)[/red]")
    raise SystemExit(1)


def main() -> None:
    """Entry point for the hatchery CLI."""
    cli()


if __name__ == "__main__":
    main()