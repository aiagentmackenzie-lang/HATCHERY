"""Report generator — produce analysis reports in Markdown and JSON.

Generates comprehensive analysis reports from all HATCHERY data sources:
sample metadata, static analysis, behavioral monitoring, network capture,
and IOC extraction.
"""

from __future__ import annotations

import json
import logging
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
        limitations: Optional[list[str]] = None,
        events: Optional[list[dict]] = None,
        evasion: Optional[dict] = None,
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
            "# HATCHERY Analysis Report",
            "",
            f"**Sample:** `{sample_name}`  ",
            f"**Date:** {now}  ",
            "**Engine:** HATCHERY v0.1.0  ",
            "",
        ]

        # Hash section
        lines.append("## File Hashes")
        lines.append("")
        lines.append("| Algorithm | Hash |")
        lines.append("|-----------|------|")
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
            duration = sandbox_results.get("duration_seconds", 0) or 0
            exit_code = sandbox_results.get("exit_code", "N/A")
            lines.append(f"- **Status:** {status}")
            lines.append(f"- **Duration:** {duration:.1f}s")
            lines.append(f"- **Exit Code:** {exit_code}")

            isolation = sandbox_results.get("isolation") or {}
            if isolation:
                boundary = isolation.get("boundary", "")
                if isolation.get("is_security_boundary"):
                    lines.append(
                        f"- **Isolation:** tier {isolation.get('tier')} "
                        f"({isolation.get('tier_name')}) — {boundary}"
                    )
                else:
                    lines.append(
                        f"- **Isolation:** tier {isolation.get('tier')} "
                        f"({isolation.get('tier_name')}) — **not a security boundary**. "
                        f"{boundary}"
                    )

            monitoring = sandbox_results.get("monitoring") or {}
            if monitoring:
                lines.append(
                    f"- **Monitoring:** `{monitoring.get('collector', 'unknown')}` "
                    f"({monitoring.get('location', 'unknown')}) — "
                    f"{monitoring.get('how', '')}"
                )
                for blind in monitoring.get("blind_spots", []):
                    lines.append(f"  - cannot see: {blind}")
                if monitoring.get("downgrade_reason"):
                    lines.append(f"  - **collector downgrade:** {monitoring['downgrade_reason']}")

            artifacts = sandbox_results.get("artifacts") or {}
            found = artifacts.get("found") or {}
            missing = artifacts.get("missing") or []
            if found or missing:
                lines.append("")
                lines.append("### Captured Artifacts")
                lines.append("")
                for key in sorted(found):
                    lines.append(f"- `{key}`: `{found[key]}`")
                for key in missing:
                    lines.append(f"- `{key}`: **not captured**")
                dropped = artifacts.get("dropped_files") or []
                if dropped:
                    lines.append(f"- dropped files: {len(dropped)}")

            if sandbox_results.get("error"):
                lines.append("")
                lines.append(f"> **Sandbox note:** {sandbox_results['error']}")

            lines.append("")

        # Behavioural detail, rendered from the normalised event stream. The
        # previous revision read `sandbox_results["strace"]["network_connections"]`,
        # a key no producer ever wrote, so this section was always empty in real
        # reports while a hand-written test fixture kept it looking alive.
        if events:
            network = [e for e in events if e.get("category") == "network"]
            if network:
                lines.append("### Network Connections")
                lines.append("")
                lines.append("| Destination | Port | Syscall | Source |")
                lines.append("|-------------|------|---------|--------|")
                for event in network[:20]:
                    try:
                        args = json.loads(event.get("args") or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    lines.append(
                        f"| {args.get('dst_ip', 'n/a')} | {args.get('dst_port', 'n/a')} "
                        f"| {event.get('syscall_name', '')} | {event.get('source', '')} |"
                    )
                lines.append("")

            counts: dict[str, int] = {}
            for event in events:
                key = event.get("syscall_name") or "unknown"
                counts[key] = counts.get(key, 0) + 1
            if counts:
                lines.append("### Most Frequent Events")
                lines.append("")
                lines.append("| Event | Count |")
                lines.append("|-------|-------|")
                for name, count in sorted(counts.items(), key=lambda kv: -kv[1])[:15]:
                    lines.append(f"| `{name}` | {count} |")
                lines.append("")

            notable = [
                e for e in events if e.get("severity") in ("high", "critical")
            ]
            if notable:
                lines.append(f"### High-Severity Events ({len(notable)})")
                lines.append("")
                for event in notable[:25]:
                    lines.append(
                        f"- `[{event.get('severity', '').upper()}]` "
                        f"{event.get('syscall_name', '')} — {event.get('raw_line', '')[:160]}"
                    )
                lines.append("")

        # Evasion assessment — the differentiator. A recon-then-quiet run's
        # *shape* matters more than its individual syscalls, so this is its own
        # section rather than being buried in the event list.
        if evasion and evasion.get("findings"):
            verdict = evasion.get("verdict", "none")
            lines.append("## Evasion Assessment")
            lines.append("")
            lines.append(
                f"**Score:** {evasion.get('score', 0)}/100 — **{verdict.upper()}**  "
            )
            lines.append(
                f"**Impact after recon:** {evasion.get('impact_score', 0)} event(s); "
                f"**recon-then-quiet:** {evasion.get('recon_then_quiet', False)}  "
            )
            if evasion.get("inconclusive"):
                lines.append("")
                lines.append(
                    "> **INCONCLUSIVE (evasive):** the sample reconnoitered and then "
                    "exited without observable impact. This is not a clean result."
                )
            lines.append("")
            lines.append("| Signal | Severity | Count | Description |")
            lines.append("|--------|:--:|--:|-------------|")
            for finding in evasion.get("findings", []):
                lines.append(
                    f"| `{finding.get('signal', '')}` | {finding.get('severity', '')} | "
                    f"{finding.get('count', 0)} | {finding.get('description', '')} |"
                )
            lines.append("")

        if limitations:
            lines.append("## What This Run Does Not Establish")
            lines.append("")
            for item in limitations:
                lines.append(f"- {item}")
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

        # Known limitations are *computed*, per run, and rendered above in the
        # "What This Run Does Not Establish" section. The previous revision
        # hardcoded a second, stale list here (Windows containers, VM
        # snapshot/restore) that contradicted the computed one — two producers
        # of the same honesty channel, guaranteed to drift.

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
        limitations: Optional[list[str]] = None,
        evasion: Optional[dict] = None,
    ) -> str:
        """Generate a JSON analysis report.

        ``limitations`` are the *computed* per-run limitations. They used to be
        a hardcoded list in this method, which meant the JSON report and the
        Markdown report could disagree about what a run did not establish.
        There is now one producer.
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
            "evasion": evasion,
            "ioc_report": ioc_report,
            "limitations": limitations or [],
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
        limitations: Optional[list[str]] = None,
        events: Optional[list[dict]] = None,
        evasion: Optional[dict] = None,
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
            sample_name,
            sample_hash,
            static_results,
            sandbox_results,
            ioc_report,
            limitations,
            events,
            evasion,
        )
        (output_dir / "report.md").write_text(md, encoding="utf-8")

        json_report = self.generate_json(
            sample_name, sample_hash, static_results, sandbox_results,
            ioc_report, limitations, evasion,
        )
        (output_dir / "report.json").write_text(json_report, encoding="utf-8")

        logger.info("Reports written to %s", output_dir)
        return output_dir