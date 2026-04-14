"""Report generator — produce analysis reports in Markdown and JSON.

Generates comprehensive analysis reports from all HATCHERY data sources:
sample metadata, static analysis, behavioral monitoring, network capture,
and IOC extraction.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate analysis reports from HATCHERY results.

    Produces Markdown reports for human consumption and JSON for
    programmatic use.
    """

    def generate_markdown(
        self,
        sample_name: str,
        sample_hash: dict,
        static_results: Optional[dict] = None,
        sandbox_results: Optional[dict] = None,
        ioc_report: Optional[dict] = None,
    ) -> str:
        """Generate a Markdown analysis report.

        Args:
            sample_name: Name of the analyzed sample.
            sample_hash: Hash information dict.
            static_results: Static analysis results.
            sandbox_results: Sandbox execution results.
            ioc_report: IOC extraction report.

        Returns:
            Markdown report string.
        """
        now = datetime.now(timezone.utc).isoformat()
        lines: list[str] = [
            f"# HATCHERY Analysis Report",
            f"",
            f"**Sample:** `{sample_name}`  ",
            f"**Date:** {now}  ",
            f"**Engine:** HATCHERY v0.1.0  ",
            f"",
        ]

        # Hash section
        lines.append("## File Hashes")
        lines.append("")
        lines.append(f"| Algorithm | Hash |")
        lines.append(f"|-----------|------|")
        lines.append(f"| MD5 | `{sample_hash.get('md5', 'N/A')}` |")
        lines.append(f"| SHA1 | `{sample_hash.get('sha1', 'N/A')}` |")
        lines.append(f"| SHA256 | `{sample_hash.get('sha256', 'N/A')}` |")
        if sample_hash.get('ssdeep'):
            lines.append(f"| SSDeep | `{sample_hash['ssdeep']}` |")
        lines.append(f"| File Size | {sample_hash.get('file_size', 0)} bytes |")
        lines.append("")

        # Static analysis
        if static_results:
            lines.append("## Static Analysis")
            lines.append("")

            # YARA matches
            yara = static_results.get("yara", {})
            if yara.get("matches"):
                lines.append("### YARA Matches")
                lines.append("")
                for match in yara["matches"]:
                    rule = match.get("rule", "unknown")
                    desc = match.get("meta", {}).get("description", "")
                    lines.append(f"- **{rule}** — {desc}")
                lines.append("")

            # capa capabilities
            capa = static_results.get("capa", {})
            if capa.get("capabilities"):
                lines.append("### Capabilities (capa)")
                lines.append("")
                for cap in capa["capabilities"]:
                    name = cap.get("name", "unknown")
                    ns = cap.get("namespace", "")
                    lines.append(f"- `{name}` ({ns})")
                lines.append("")

            # Packer detection
            packer = static_results.get("packer", {})
            if packer.get("packers"):
                lines.append("### Packer Detection")
                lines.append("")
                for p in packer["packers"]:
                    lines.append(f"- **{p.get('name', 'Unknown')}** (confidence: {p.get('confidence', 'N/A')})")
                lines.append("")

        # Behavioral analysis
        if sandbox_results:
            lines.append("## Behavioral Analysis")
            lines.append("")

            status = sandbox_results.get("status", "unknown")
            duration = sandbox_results.get("duration_seconds", 0)
            exit_code = sandbox_results.get("exit_code", "N/A")
            lines.append(f"- **Status:** {status}")
            lines.append(f"- **Duration:** {duration:.1f}s")
            lines.append(f"- **Exit Code:** {exit_code}")
            lines.append("")

            # Strace summary
            strace = sandbox_results.get("strace", {})
            if strace:
                event_count = strace.get("parsed_events", 0)
                lines.append(f"### Syscall Trace ({event_count} events)")
                lines.append("")

                # Network connections
                conns = strace.get("network_connections", [])
                if conns:
                    lines.append("#### Network Connections")
                    lines.append("")
                    lines.append("| IP | Port | PID |")
                    lines.append("|----|------|-----|")
                    for conn in conns[:20]:
                        lines.append(f"| {conn.get('ip', 'N/A')} | {conn.get('port', 'N/A')} | {conn.get('pid', 'N/A')} |")
                    lines.append("")

                # Process operations
                procs = strace.get("process_operations", [])
                if procs:
                    lines.append("#### Process Executions")
                    lines.append("")
                    for proc in procs[:10]:
                        lines.append(f"- `{proc.get('path', 'N/A')}` (PID {proc.get('pid', 'N/A')})")
                    lines.append("")

        # IOCs
        if ioc_report:
            lines.append("## Indicators of Compromise")
            lines.append("")

            summary = ioc_report.get("summary", {})
            if summary:
                lines.append("### Summary")
                lines.append("")
                lines.append("| Type | Count |")
                lines.append("|------|-------|")
                for ioc_type, count in sorted(summary.items()):
                    lines.append(f"| {ioc_type} | {count} |")
                lines.append("")

            iocs = ioc_report.get("iocs", [])
            if iocs:
                lines.append("### Detailed IOCs")
                lines.append("")
                for ioc in iocs:
                    severity = ioc.get("severity", "unknown")
                    lines.append(
                        f"- **[{severity.upper()}]** `{ioc.get('value', 'N/A')}` "
                        f"({ioc.get('type', 'unknown')}) — {ioc.get('context', '')}"
                    )
                lines.append("")

        # Known limitations
        lines.append("## Known Limitations")
        lines.append("")
        lines.append("1. **Docker ≠ VM isolation** — Containers share the host kernel. Evasive malware using VM detection will not be fooled.")
        lines.append("2. **ptrace detection** — Advanced anti-debug malware can detect strace.")
        lines.append("3. **Windows malware** — Dynamic execution requires Windows containers (not yet supported).")
        lines.append("4. **No VM snapshot/restore** — Each analysis spins a fresh container.")
        lines.append("")

        footer = "---\n*Generated by HATCHERY — watch it hatch, watch it burn.*\n"
        lines.append(footer)

        return "\n".join(lines)

    def generate_json(
        self,
        sample_name: str,
        sample_hash: dict,
        static_results: Optional[dict] = None,
        sandbox_results: Optional[dict] = None,
        ioc_report: Optional[dict] = None,
    ) -> str:
        """Generate a JSON analysis report.

        Args:
            sample_name: Name of the analyzed sample.
            sample_hash: Hash information dict.
            static_results: Static analysis results.
            sandbox_results: Sandbox execution results.
            ioc_report: IOC extraction report.

        Returns:
            JSON report string.
        """
        report = {
            "generator": "HATCHERY",
            "version": "0.1.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sample": {
                "name": sample_name,
                "hashes": sample_hash,
            },
            "static_analysis": static_results,
            "behavioral_analysis": sandbox_results,
            "ioc_report": ioc_report,
            "limitations": [
                "Docker containers share the host kernel (weaker than VM isolation)",
                "Advanced anti-debug malware can detect strace/ptrace",
                "Windows PE dynamic execution not yet supported",
                "No VM snapshot/restore between runs",
            ],
        }
        return json.dumps(report, indent=2, default=str)

    def write_report(
        self,
        output_dir: Path,
        sample_name: str,
        sample_hash: dict,
        static_results: Optional[dict] = None,
        sandbox_results: Optional[dict] = None,
        ioc_report: Optional[dict] = None,
    ) -> Path:
        """Write both Markdown and JSON reports to a directory.

        Args:
            output_dir: Directory to write reports.
            sample_name: Sample name for filenames.

        Returns:
            Path to the output directory.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        md = self.generate_markdown(
            sample_name, sample_hash, static_results, sandbox_results, ioc_report
        )
        (output_dir / "report.md").write_text(md, encoding="utf-8")

        json_report = self.generate_json(
            sample_name, sample_hash, static_results, sandbox_results, ioc_report
        )
        (output_dir / "report.json").write_text(json_report, encoding="utf-8")

        logger.info("Reports written to %s", output_dir)
        return output_dir