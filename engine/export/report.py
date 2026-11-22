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


def _hex(value: object) -> str:
    """A stable ``0x`` rendering for an address from a possibly hand-edited doc."""
    if isinstance(value, int):
        return f"0x{value:x}"
    if isinstance(value, str):
        try:
            return f"0x{int(value, 0):x}"
        except ValueError:
            return value
    return "0x0" if value is None else str(value)


def _section_list(sections: list) -> str:
    """First sections of a PE/ELF as ``name (flags, size)``, bounded and safe."""
    rendered: list[str] = []
    for section in sections[:20]:
        if not isinstance(section, dict):
            continue
        name = str(section.get("name") or "<unnamed>")
        size = section.get("raw_size", section.get("size", 0))
        flags = str(section.get("flags") or "")
        suffix = f", {flags}" if flags else ""
        rendered.append(f"`{name}` ({size} B{suffix})")
    if len(sections) > 20:
        rendered.append(f"+{len(sections) - 20} more")
    return ", ".join(rendered) or "none"


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
        attack_version: str = "",
        ocsf_schema_version: str = "",
        emulation: Optional[dict] = None,
        triage: Optional[dict] = None,
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
        if attack_version or ocsf_schema_version:
            lines.append("## Framework Versions")
            lines.append("")
            if attack_version:
                lines.append(
                    f"- **MITRE ATT&CK:** {attack_version} "
                    "(mapping validated against the pinned dataset)"
                )
            if ocsf_schema_version:
                lines.append(f"- **OCSF schema:** {ocsf_schema_version}")
            lines.append("")

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

            # Binary structure first: the format is the most basic fact about a
            # sample, and D38 made it reach the bundle. Absent sections are
            # omitted; ``None`` means the sample is not that format.
            self._render_binary_sections(lines, static_results)

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

            # Delivery-format intake. The container and every file extracted
            # from it, plus anything detected but deliberately not unpacked —
            # so a document can never render as an empty static section.
            delivery = static_results.get("delivery") or {}
            if delivery.get("format") and delivery.get("format") != "unknown":
                lines.append("### Delivery Format")
                lines.append("")
                detail = delivery.get("format_detail") or ""
                lines.append(f"- **Format:** `{delivery['format']}`{' — ' + detail if detail else ''}")
                if delivery.get("flags"):
                    lines.append(
                        "- **Flags:** "
                        + ", ".join(f"`{flag}`" for flag in delivery["flags"])
                    )
                children = delivery.get("children") or []
                if children:
                    lines.append(f"- **Extracted files:** {len(children)}")
                    lines.append("")
                    lines.append("| Extracted file | Size | Format | SHA256 | Flags |")
                    lines.append("|---|---:|---|---|---|")
                    for child in children[:40]:
                        digest = str(child.get("sha256", ""))
                        lines.append(
                            f"| `{child.get('name', '')}` | {child.get('size', 0)} "
                            f"| {child.get('format', '')} | `{digest[:16]}…` "
                            f"| {', '.join(child.get('flags') or [])} |"
                        )
                    lines.append("")
                unsupported = delivery.get("unsupported") or []
                if unsupported:
                    lines.append("**Detected but not extracted:**")
                    lines.append("")
                    for item in unsupported:
                        lines.append(
                            f"- `{item.get('path', '')}` ({item.get('format', '')})"
                            f" — {item.get('reason', '')}"
                        )
                    lines.append("")

                # Format-specific facts the extractors decoded (a shell link's
                # target and arguments, an ISO's volume identifier).
                details = delivery.get("details") or {}
                link = details.get("link") or {}
                if link:
                    lines.append("**Shell link:**")
                    lines.append("")
                    for key, label in (
                        ("target", "target"), ("target_idlist", "target (ID list)"),
                        ("network_share", "network share"), ("arguments", "arguments"),
                        ("working_dir", "working dir"), ("description", "description"),
                        ("icon_location", "icon"),
                    ):
                        if link.get(key):
                            lines.append(f"- {label}: `{link[key]}`")
                    for target in link.get("environment_target") or []:
                        lines.append(f"- environment target: `{target}`")
                    lines.append("")
                iso = details.get("iso") or {}
                if iso:
                    volume = iso.get("volume_identifier") or ""
                    flavor = " (Joliet)" if iso.get("joliet") else ""
                    lines.append(f"**ISO9660:** volume `{volume}`{flavor}")
                    lines.append("")
                ole_details = details.get("ole") or {}
                embedded_packages = [
                    name
                    for info in ole_details.values()
                    for name in (info.get("embedded") or [])
                ]
                if embedded_packages:
                    lines.append("**OLE embedded packages:**")
                    lines.append("")
                    for name in embedded_packages:
                        lines.append(f"- `{name}`")
                    lines.append("")
                rtf_details = details.get("rtf") or {}
                rtf_count = int(rtf_details.get("objects") or 0)
                if rtf_count:
                    lines.append("**RTF embedded objects:**")
                    lines.append("")
                    lines.append(f"- objects: {rtf_count}")
                    rtf_classes = rtf_details.get("objclasses") or []
                    if rtf_classes:
                        lines.append(
                            "- classes: " + ", ".join(f"`{name}`" for name in rtf_classes)
                        )
                    lines.append("")
                if delivery.get("truncated"):
                    lines.append(
                        "> **Note:** extraction stopped at a configured limit; the "
                        "file list above is incomplete."
                    )
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

        if emulation:
            lines.extend(self._render_emulation(emulation))

        if triage:
            lines.extend(self._render_triage(triage))

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

    def _render_binary_sections(self, lines: list[str], static_results: dict) -> None:
        """PE/ELF structure from the bundle's ``static.pe``/``static.elf`` (D38).

        These sections are engine-produced facts, not analysis opinion. The
        renderer stays bounded (first 20 sections, first 10 imports) and reads
        defensively: a hand-edited or truncated ``analysis.json`` must render
        what is there without raising.
        """
        pe = static_results.get("pe")
        if isinstance(pe, dict) and pe.get("is_valid_pe"):
            lines.append("### PE Structure")
            lines.append("")
            machine = str(pe.get("machine_type") or "unknown")
            if pe.get("is_64bit"):
                machine += ", 64-bit"
            lines.append(f"- **Machine:** {machine}")
            if pe.get("subsystem"):
                lines.append(f"- **Subsystem:** {pe['subsystem']}")
            if pe.get("compile_timestamp"):
                lines.append(f"- **Compiled:** {pe['compile_timestamp']}")
            lines.append(f"- **Entry point:** `{_hex(pe.get('entry_point'))}`")
            sections = pe.get("sections") or []
            lines.append(f"- **Sections ({len(sections)}):** " + _section_list(sections))
            imports = pe.get("imports") or []
            if imports:
                rendered = [
                    f"`{row.get('dll', '?')}!{row.get('function', '?')}`"
                    for row in imports[:10]
                    if isinstance(row, dict)
                ]
                more = f" (+{len(imports) - 10} more)" if len(imports) > 10 else ""
                lines.append(f"- **Imports ({len(imports)}):** " + ", ".join(rendered) + more)
            else:
                lines.append("- **Imports:** none")
            exports = pe.get("exports") or []
            lines.append(f"- **Exports:** {len(exports)}")
            indicators = pe.get("suspicious_indicators") or []
            if indicators:
                lines.append("- **Suspicious indicators:**")
                for indicator in indicators[:10]:
                    lines.append(f"  - {indicator}")
            lines.append("")

        elf = static_results.get("elf")
        if isinstance(elf, dict) and elf.get("is_valid_elf"):
            lines.append("### ELF Structure")
            lines.append("")
            architecture = str(elf.get("arch") or "unknown")
            if elf.get("bits"):
                architecture += f", {elf['bits']}-bit"
            if elf.get("endian"):
                architecture += f", {elf['endian']}"
            lines.append(f"- **Architecture:** {architecture}")
            if elf.get("elf_type"):
                lines.append(f"- **Type:** {elf['elf_type']}")
            lines.append(f"- **Entry point:** `{_hex(elf.get('entry_point'))}`")
            sections = elf.get("sections") or []
            lines.append(f"- **Sections ({len(sections)}):** " + _section_list(sections))
            libraries = elf.get("dynamic_libraries") or []
            lines.append(
                "- **Dynamic libraries:** " + (", ".join(map(str, libraries[:10])) or "none")
            )
            exported = elf.get("exported_symbols") or []
            imported = elf.get("imported_symbols") or []
            lines.append(f"- **Symbols:** {len(exported)} exported, {len(imported)} imported")
            security = elf.get("security") or {}
            if isinstance(security, dict):
                lines.append(
                    "- **Hardening:** "
                    + ", ".join(
                        f"{label} {'on' if security.get(key) else 'off'}"
                        for key, label in (
                            ("has_nx", "NX"),
                            ("is_pie", "PIE"),
                            ("has_relro", "RELRO"),
                            ("has_full_relro", "full RELRO"),
                            ("has_canary", "canary"),
                            ("is_stripped", "stripped"),
                        )
                    )
                )
            indicators = elf.get("suspicious_indicators") or []
            if indicators:
                lines.append("- **Suspicious indicators:**")
                for indicator in indicators[:10]:
                    lines.append(f"  - {indicator}")
            lines.append("")

    def _render_triage(self, triage: dict) -> list[str]:
        """Render the advisory LLM triage section, grounded and clearly labelled.

        The heading says *advisory* and *local* on purpose: this section is the
        model's summary of the engine's evidence, not a new source of truth, and
        every finding is shown with the evidence ids it cited.
        """
        lines: list[str] = ["## AI Triage (advisory, local model)", ""]
        if not triage.get("available"):
            lines.append(
                f"Triage was **not produced** ({triage.get('status', 'unavailable')}): "
                f"{triage.get('reason') or 'not available'}."
            )
            lines.append("")
            return lines

        if triage.get("allowed_remote") or triage.get("allowed_cloud_model"):
            lines.append(
                "> ⚠️ **Remote model permitted.** Sample-derived text left this "
                "machine for this triage. This is not the default."
            )
            lines.append("")

        lines.append(
            f"- **Model:** `{triage.get('model', 'unknown')}` "
            f"(prompt contract {triage.get('prompt_version', '?')}/"
            f"`{str(triage.get('contract_hash', ''))[:12]}`)"
        )
        lines.append(
            f"- **Verdict:** `{triage.get('verdict', 'inconclusive')}` "
            f"(model confidence {int(triage.get('confidence') or 0)}/100)"
        )
        lines.append(
            f"- **Grounded in:** {len(triage.get('findings') or [])} finding(s) over "
            f"{int(triage.get('evidence_ids') or 0)} citable evidence item(s)"
        )
        if triage.get("evidence_truncated"):
            lines.append(
                "- **Note:** the evidence set was truncated to fit the model context."
            )
        lines.append("")

        if triage.get("summary"):
            lines.append(triage["summary"])
            lines.append("")

        findings = triage.get("findings") or []
        if findings:
            lines.append("### Grounded findings")
            lines.append("")
            for finding in findings:
                citations = ", ".join(
                    f"`{cid}`" for cid in (finding.get("grounding") or [])
                )
                lines.append(f"- {finding.get('claim', '')} — cited: {citations}")
                if finding.get("technique_ids"):
                    lines.append(
                        "  - ATT&CK (model-suggested, unvalidated): "
                        + ", ".join(f"`{t}`" for t in finding["technique_ids"])
                    )
            lines.append("")

        dropped = int(triage.get("findings_dropped") or 0)
        if dropped:
            lines.append(
                f"**{dropped} finding(s) were discarded** because their citations did "
                "not resolve to evidence in this run. The verdict reflects only what "
                "could be grounded."
            )
            lines.append("")

        if triage.get("not_established"):
            lines.append("### Not established by this run")
            lines.append("")
            lines.extend(f"- {item}" for item in triage["not_established"])
            lines.append("")

        if triage.get("recommended_actions"):
            lines.append("### Recommended actions")
            lines.append("")
            lines.extend(f"- {item}" for item in triage["recommended_actions"])
            lines.append("")

        return lines

    def _render_emulation(self, emulation: dict) -> list[str]:
        """Render the emulation section, including its declared limits."""
        lines: list[str] = ["## Emulation (Windows PE)", ""]
        if not emulation.get("available"):
            lines.append(
                f"Emulation was **not run**: {emulation.get('reason') or 'not available'}."
            )
            lines.append("")
            return lines

        lines.append(
            f"- **Emulator:** {emulation.get('emulator', 'speakeasy')} "
            f"{emulation.get('emulator_version', '?')} "
            f"(report schema `{str(emulation.get('schema_hash', ''))[:12]}`)"
        )
        lines.append(f"- **Status:** {emulation.get('status', 'unknown')}")
        if emulation.get("flags"):
            lines.append(
                "- **Flags:** " + ", ".join(f"`{flag}`" for flag in emulation["flags"])
            )
        lines.append(
            f"- **API calls:** {int(emulation.get('api_calls') or 0)}; "
            f"**events written:** {int(emulation.get('events_written') or 0)}"
        )
        if emulation.get("runtime_seconds") is not None:
            lines.append(f"- **Emulated runtime:** {emulation.get('runtime_seconds')}s")
        if emulation.get("unsupported_apis"):
            lines.append(
                "- **INCONCLUSIVE:** unimplemented API(s): "
                + ", ".join(f"`{api}`" for api in emulation["unsupported_apis"])
            )
        lines.append(
            "> Emulation interprets x86/x64 in a software CPU; the sample did not "
            "execute natively. It is not an isolation boundary and is not ground truth."
        )
        lines.append("")

        config = emulation.get("config") or {}
        endpoints = config.get("network_endpoints") or []
        if endpoints:
            lines.append("### Extracted Configuration")
            lines.append("")
            lines.append("| Endpoint | Port | Protocol | Source |")
            lines.append("|---|---:|---|---|")
            for endpoint in endpoints:
                lines.append(
                    f"| `{endpoint.get('server', '')}` | {endpoint.get('port', '')} "
                    f"| {endpoint.get('protocol', '')} | {endpoint.get('kind', '')} |"
                )
            lines.append("")
        for label, key in (
            ("User agents", "user_agents"),
            ("Mutexes", "mutexes"),
        ):
            values = config.get(key) or []
            if values:
                lines.append(f"- **{label}:** " + ", ".join(f"`{v}`" for v in values))
        for key in config.get("registry") or []:
            marker = " (persistence)" if key.get("persistence") else ""
            lines.append(
                f"- **Registry[{key.get('kind', '')}]:** `{key.get('path', '')}`"
                f" value `{key.get('value_name', '')}`{marker}"
            )
        for dropped in config.get("dropped_files") or []:
            lines.append(
                f"- **Dropped:** `{dropped.get('path', '')}` "
                f"sha256 `{str(dropped.get('sha256', ''))[:16]}`"
            )
        lines.append("")

        capa = emulation.get("capa_dynamic") or {}
        capabilities = capa.get("capabilities") or []
        snapshots = emulation.get("snapshots") or {}
        lines.append("### capa_dynamic (capa over memory snapshots)")
        lines.append("")
        lines.append(
            f"- Snapshots decoded: {int(snapshots.get('regions_decoded') or 0)} "
            f"of {int(snapshots.get('regions_available') or snapshots.get('regions_selected') or 0)} "
            f"candidate region(s); capa ran on "
            f"{int(snapshots.get('capa_regions') or 0)}"
        )
        if capabilities:
            for capability in capabilities:
                lines.append(
                    f"- `{capability.get('name', '')}` ({capability.get('namespace', '')})"
                )
        else:
            lines.append(
                "- No capabilities found in the captured memory. This is **not** a "
                "clean result: capa_dynamic only sees regions the emulator captured."
            )
        lines.append("")
        return lines

    def generate_json(
        self,
        sample_name: str,
        sample_hash: dict,
        static_results: Optional[dict] = None,
        sandbox_results: Optional[dict] = None,
        ioc_report: Optional[dict] = None,
        limitations: Optional[list[str]] = None,
        evasion: Optional[dict] = None,
        attack_version: str = "",
        ocsf_schema_version: str = "",
        emulation: Optional[dict] = None,
        triage: Optional[dict] = None,
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
            "delivery": (static_results or {}).get("delivery"),
            "behavioral_analysis": sandbox_results,
            "evasion": evasion,
            "emulation": emulation,
            "triage": triage,
            "ioc_report": ioc_report,
            "limitations": limitations or [],
            "framework_versions": {
                "mitre_attack": attack_version,
                "ocsf_schema": ocsf_schema_version,
            },
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
        attack_version: str = "",
        ocsf_schema_version: str = "",
        emulation: Optional[dict] = None,
        triage: Optional[dict] = None,
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
            attack_version,
            ocsf_schema_version,
            emulation,
            triage,
        )
        (output_dir / "report.md").write_text(md, encoding="utf-8")

        json_report = self.generate_json(
            sample_name, sample_hash, static_results, sandbox_results,
            ioc_report, limitations, evasion, attack_version, ocsf_schema_version,
            emulation, triage,
        )
        (output_dir / "report.json").write_text(json_report, encoding="utf-8")

        logger.info("Reports written to %s", output_dir)
        return output_dir