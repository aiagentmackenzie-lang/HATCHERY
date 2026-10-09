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
import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Optional

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


def _run_delivery_intake(file: Path, results_dir: Path) -> tuple[Any, dict]:
    """Open a delivery container and statically analyse everything inside.

    The single intake path (``extract_delivery``) is called exactly here. Every
    extracted child is hashed and run through the cheap static stages (YARA,
    strings, packer detection) so its own IOCs reach the IOC extractor. The
    children are **not** detonated, and the run says so in its limitations.
    """
    from engine.intake.delivery import extract_delivery
    from engine.intake.hasher import MultiHasher
    from engine.intake.strings import StringExtractor
    from engine.static.yara_scanner import YARAScanner
    from engine.static.packer_detect import PackerDetector

    result = extract_delivery(file, results_dir / "delivery")

    hasher = MultiHasher()
    string_extractor = StringExtractor()
    yara_scanner = YARAScanner()
    packer_detector = PackerDetector()
    for child in result.children:
        try:
            child.static = {
                "hashes": hasher.hash_file(child.path).to_dict(),
                "strings": string_extractor.extract(child.path).to_dict(),
                "yara": yara_scanner.scan(child.path).to_dict(),
                "packer": packer_detector.detect(child.path).to_dict(),
            }
        except Exception as exc:  # a child must never abort the run
            result.errors.append(f"{child.name}: static analysis failed: {exc}")

    return result, result.to_dict()


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose/debug logging")
def cli(verbose: bool) -> None:
    """HATCHERY — Docker-based malware sandbox engine.

    Watch it hatch. Watch it burn.
    """
    _setup_logging(verbose)


@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--timeout", default=120, help="Sandbox timeout in seconds")
@click.option("--output", "-o", type=click.Path(path_type=Path), help="Output directory")
@click.option("--no-sandbox", is_flag=True, help="Skip sandbox execution (static only)")
def submit(file: Path, timeout: int, output: Optional[Path], no_sandbox: bool) -> None:
    """Submit a sample for full analysis.

    Runs static analysis (hashes, strings, YARA, capa, packer detection)
    and optionally detonates in the sandbox container.
    """
    task_id = uuid.uuid4().hex[:12]
    console.print(Panel(
        f"[bold orange_red1]HATCHERY[/bold orange_red1] — Submitting sample for analysis\n"
        f"Task ID: [cyan]{task_id}[/cyan]\n"
        f"File: [green]{file.name}[/green]",
        title="🔴 New Analysis",
    ))

    results_dir = output or Path(f"results/{task_id}")
    results_dir.mkdir(parents=True, exist_ok=True)

    # Initialize all analysis modules
    from engine.intake.uploader import SampleUploader
    from engine.intake.hasher import MultiHasher
    from engine.intake.strings import StringExtractor
    from engine.intake.pe_analyzer import PEAnalyzer
    from engine.intake.elf_analyzer import ELFAnalyzer
    from engine.intake.delivery import DeliveryFormat
    from engine.static.yara_scanner import YARAScanner
    from engine.static.capa_scanner import CapaScanner
    from engine.static.packer_detect import PackerDetector
    from engine.ioc.extractor import IOCExtractor
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

    uploader = SampleUploader()
    metadata = uploader.upload(file)

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
    strings = string_extractor.extract(file)
    console.print(f"  URLs: [red]{len(strings.urls)}[/red]")
    console.print(f"  IPs: [red]{len(strings.ips)}[/red]")
    console.print(f"  Domains: [red]{len(strings.domains)}[/red]")
    console.print(f"  Emails: [red]{len(strings.emails)}[/red]")
    console.print(f"  Registry keys: [red]{len(strings.registry_keys)}[/red]")
    console.print(f"  Total strings: [dim]{len(strings.all_strings)}[/dim]")

    # PE/ELF analysis
    if metadata.file_type == "PE":
        console.print("\n[bold]▸ PE Analysis[/bold]")
        pe_analyzer = PEAnalyzer()
        pe_result = pe_analyzer.analyze(file)
        if pe_result.is_valid_pe:
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
        elf_result = elf_analyzer.analyze(file)
        if elf_result.is_valid_elf:
            console.print(f"  Architecture: [cyan]{elf_result.arch}[/cyan]")
            console.print(f"  Type: [cyan]{elf_result.elf_type}[/cyan]")
            console.print(f"  Sections: [cyan]{len(elf_result.sections)}[/cyan]")
            console.print(f"  Security: NX={elf_result.security.has_nx}, PIE={elf_result.security.is_pie}")

    # Phase 1: Static analysis
    console.print("\n[bold]▸ Static Analysis[/bold]")

    # YARA scanning
    console.print("\n  [bold]YARA Scanning...[/bold]")
    yara_scanner = YARAScanner()
    yara_result = yara_scanner.scan(file)
    console.print(f"  Rules loaded: [cyan]{yara_result.rules_loaded}[/cyan]")
    console.print(f"  Matches: [red]{len(yara_result.matches)}[/red]")
    _print_yara_results(yara_result.to_dict())

    # capa analysis
    console.print("\n  [bold]capa Analysis...[/bold]")
    capa_scanner = CapaScanner()
    capa_result = capa_scanner.scan(file)
    console.print(f"  Available: [cyan]{capa_result.is_available}[/cyan]")
    if capa_result.is_available:
        console.print(f"  Capabilities: [red]{len(capa_result.capabilities)}[/red]")
        _print_capa_results(capa_result.to_dict())

    # Packer detection
    console.print("\n  [bold]Packer Detection...[/bold]")
    packer_detector = PackerDetector()
    packer_result = packer_detector.detect(file)
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

                # Parse the syscall source that this tier's collector produced.
                # Tier 2 uses gVisor's Sentry trace; tier 1 uses in-guest strace.
                syscall_result = None
                if sandbox_result.gvisor_trace_log:
                    from engine.monitor.gvisor_strace import GvisorStraceParser
                    console.print("\n  [bold]Parsing gVisor Sentry trace...[/bold]")
                    gvisor_path = Path(sandbox_result.gvisor_trace_log)
                    if gvisor_path.exists():
                        gvisor_result = GvisorStraceParser().parse_file(gvisor_path)
                        syscall_result = gvisor_result
                        console.print(
                            f"  Events parsed: [cyan]{gvisor_result.parsed_events}[/cyan] "
                            f"(source: gvisor-sentry)"
                        )
                elif sandbox_result.strace_log:
                    from engine.monitor.strace_parser import StraceParser
                    console.print("\n  [bold]Parsing syscall log...[/bold]")
                    strace_path = Path(sandbox_result.strace_log)
                    if strace_path.exists():
                        strace_result = StraceParser().parse_file(strace_path)
                        syscall_result = strace_result
                        console.print(f"  Events parsed: [cyan]{strace_result.parsed_events}[/cyan]")
                elif sandbox_result.gvisor_trace_error:
                    console.print(
                        f"  [yellow]gVisor Sentry trace unavailable: "
                        f"{sandbox_result.gvisor_trace_error}[/yellow]"
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
                        gvisor_result.events, sample_name=file.name
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
                    inotify_log_path = sandbox_result.artifacts.inotify_log
                    line_count = len(
                        inotify_log_path.read_text(errors="replace").splitlines()
                    )
                    console.print(f"  Filesystem events: [red]{line_count}[/red]")

                # Analyze network capture if available
                if sandbox_result.tcpdump_pcap:
                    from engine.monitor.network_capture import NetworkCapture
                    console.print("\n  [bold]Analyzing network capture...[/bold]")
                    net_capture = NetworkCapture()
                    pcap_path = Path(sandbox_result.tcpdump_pcap)
                    if pcap_path.exists():
                        net_result = net_capture.analyze_pcap(pcap_path)
                        console.print(f"  Connections: [cyan]{len(net_result.connections)}[/cyan]")
                        console.print(f"  DNS queries: [cyan]{len(net_result.dns_queries)}[/cyan]")
                        console.print(f"  C2 detections: [red]{len(net_result.c2_detections)}[/red]")

                if sandbox_result.error:
                    sandbox_error = sandbox_result.error
            else:
                console.print("  [yellow]Sandbox not ready — skipping detonation[/yellow]")
                for problem in problems:
                    console.print(f"    • [yellow]{problem}[/yellow]")
        except Exception as e:
            console.print(f"  [red]Sandbox error: {e}[/red]")
            sandbox_error = str(e)

    # IOC Extraction
    console.print("\n[bold]▸ IOC Extraction[/bold]")
    extractor = IOCExtractor()

    static_data = {
        "strings": strings.to_dict(),
        "yara": yara_result.to_dict(),
        "capa": capa_result.to_dict(),
        "packer": packer_result.to_dict(),
        "delivery": delivery_dict,
    }

    ioc_report = extractor.extract(static_data=static_data)
    _print_iocs(ioc_report.to_dict())

    # MITRE ATT&CK mapping
    console.print("\n[bold]▸ MITRE ATT&CK Mapping[/bold]")
    mapper = MITREMapper()
    mapped_events = None
    if syscall_result is not None:
        mapped_events = syscall_result
    file_watch_data = None
    if inotify_log_path is not None:
        from engine.bundle import events_from_inotify

        file_watch_data = {"events": events_from_inotify(inotify_log_path)}
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
    )
    bundle = AnalysisBundle(
        task_id=task_id,
        sample={
            "file_name": file.name,
            "file_path": str(file),
            "file_size": hash_result.file_size,
            "file_type": metadata.file_type,
            **hash_result.to_dict(),
        },
        isolation=sandbox_result_dict.get("isolation") if sandbox_result_dict else None,
        static=static_data,
        sandbox=sandbox_result_dict,
        iocs=ioc_report.to_dict().get("iocs", []),
        mitre=mitre_result.to_dict(),
        evasion=evasion_dict,
        events=events,
        limitations=limitations,
        errors=[sandbox_error] if sandbox_error else [],
    )
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
        sample_name=file.name,
        sample_hash=hash_result.to_dict(),
        static_results=static_data,
        sandbox_results=sandbox_result_dict,
        ioc_report=ioc_report.to_dict(),
        limitations=limitations,
        events=events,
        evasion=evasion_dict,
        attack_version=mitre_result.attack_version,
        ocsf_schema_version=OCSF_SCHEMA_VERSION,
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
        sample_name=file.name,
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
        sample_name=file.name,
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
        sample_name=file.name,
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

    if limitations:
        console.print(render_limitations(limitations), highlight=False)

    console.print(Panel(
        f"Task ID: [cyan]{task_id}[/cyan]\n"
        f"Status: [green]completed[/green]\n"
        f"Results: [cyan]{results_dir}[/cyan]",
        title="✅ Analysis Complete",
    ))


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
def push(run_dir: Path, target_kind: str, url: Optional[str], token: Optional[str],
         collection: Optional[str], insecure: bool) -> None:
    """Push a run's STIX bundle to MISP or OpenCTI.

    Reads the ``stix_bundle.json`` the engine already wrote — it does not
    re-derive STIX, so there is still exactly one producer. Fail-closed: a
    non-2xx response or a transport error is reported and exits non-zero.
    """
    from engine.export.push import PushTarget, push_stix, write_push_result

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
@click.argument("file", type=click.Path(exists=True, path_type=Path))
def static(file: Path) -> None:
    """Run static analysis only (no sandbox execution)."""
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

    # Strings
    string_extractor = StringExtractor()
    strings = string_extractor.extract(file)
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
    yara_scanner = YARAScanner()
    yara_result = yara_scanner.scan(file)
    _print_yara_results(yara_result.to_dict())

    # capa
    console.print("\n[bold]capa Analysis[/bold]")
    capa_scanner = CapaScanner()
    capa_result = capa_scanner.scan(file)
    _print_capa_results(capa_result.to_dict())

    # Packer
    console.print("\n[bold]Packer Detection[/bold]")
    packer_detector = PackerDetector()
    packer_result = packer_detector.detect(file)
    _print_packer_results(packer_result.to_dict())


@cli.command()
def build() -> None:
    """Build the sandbox Docker image."""
    console.print("[bold]Building HATCHERY sandbox Docker image...[/bold]")

    try:
        from engine.sandbox.container import ContainerManager
        manager = ContainerManager()
        tag = manager.build_image()
        console.print(f"[green]✓ Built sandbox image: {tag}[/green]")
    except FileNotFoundError as e:
        console.print(f"[red]Dockerfile not found: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Build failed: {e}[/red]")
        console.print("[dim]Make sure Docker is running and you have permission[/dim]")


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