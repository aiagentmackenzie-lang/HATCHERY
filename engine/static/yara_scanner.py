"""YARA rule scanning — YARA-X backend.

Uses **YARA-X** (``yara_x``), the Rust rewrite of YARA, which went 1.0 stable in
June 2025 and is where all new YARA development happens. The original YARA is in
maintenance mode: bug fixes only, no new modules. VirusTotal runs YARA-X in
production for Livehunt and Retrohunt.

Two things this module gives us beyond pattern matching:

* **Memory safety.** YARA-X parses hostile binaries. It is written in Rust
  precisely because the C implementation was a memory-safety liability in that
  position.
* **Compiler lints as a CI gate.** ``lint_rules`` turns rule hygiene into a
  build failure: rule-name convention, required metadata, duplicate features,
  and unreachable rules. See ``hatchery rules lint``.

API note for maintainers: ``Compiler.build()`` **resets the compiler**, so
``errors()`` and ``warnings()`` must be read *before* calling ``build()``.
Reading them afterwards always returns empty lists and silently disables every
lint. ``lint_rules`` depends on that ordering.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, cast

logger = logging.getLogger(__name__)

try:
    import yara_x

    HAS_YARA = True
except ImportError:  # pragma: no cover - depends on the environment
    HAS_YARA = False
    logger.error(
        "yara_x is not installed — YARA scanning is disabled. Install with: pip install yara-x"
    )

# Default rules directory (relative to this file)
RULES_DIR = Path(__file__).parent / "rules"

# Convention enforced by the CI lint.
RULE_NAME_PATTERN = r"^HATCHERY_"
REQUIRED_METADATA = ("description", "severity")
# Test/utility rules legitimately have no ATT&CK mapping.
ATTACK_MAPPING_EXEMPT = ("EICAR", "Test")

# Compiler warnings we have reviewed and accepted, with the reason. Anything not
# listed here is surfaced as UNACCEPTED in the lint report so a new warning is
# visible rather than buried among known ones.
ACCEPTED_WARNINGS: dict[str, str] = {
    "general.yar: slow pattern": (
        "Base64-payload heuristic. The quantifier is bounded to 512 to cap cost; "
        "YARA-X still flags the character class. Revisit if scan times grow."
    ),
}

DEFAULT_SCAN_TIMEOUT_SECONDS = 60


@dataclass
class YARAMatch:
    """A single YARA rule match."""

    rule: str
    namespace: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    matched_strings: list[dict] = field(default_factory=list)

    @property
    def severity(self) -> str:
        value = self.meta.get("severity", "unknown")
        return str(value).lower()

    @property
    def attack(self) -> str:
        return str(self.meta.get("mitre_attck", ""))

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "severity": self.severity,
            "mitre_attck": self.attack,
            "matched_strings": self.matched_strings,
        }


@dataclass
class YARAResult:
    """Complete YARA scan result."""

    rules_loaded: int = 0
    rules_sources: list[str] = field(default_factory=list)
    matches: list[YARAMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    backend: str = "yara-x"
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "rules_loaded": self.rules_loaded,
            "rules_sources": self.rules_sources,
            "matches": [m.to_dict() for m in self.matches],
            "scan_time_ms": self.scan_time_ms,
            "error": self.error,
        }

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0

    @property
    def highest_severity(self) -> str:
        order = ["critical", "high", "medium", "low", "info", "unknown"]
        for level in order:
            if any(m.severity == level for m in self.matches):
                return level
        return "none"


class YARAScanner:
    """Compile HATCHERY's rule sets and scan samples against them."""

    def __init__(
        self,
        rules_dir: Path = RULES_DIR,
        timeout_seconds: int = DEFAULT_SCAN_TIMEOUT_SECONDS,
    ) -> None:
        self.rules_dir = rules_dir
        self.timeout_seconds = timeout_seconds
        self._compiled: Optional[object] = None
        self._scanner: Optional[object] = None
        self._rules_loaded = 0
        self._rules_sources: list[str] = []
        self._compile_error: Optional[str] = None

    # ------------------------------------------------------------------ rules

    def _find_rule_files(self) -> dict[str, list[Path]]:
        """Map namespace name -> list of rule files.

        Each subdirectory of the rules dir becomes a namespace, so rules with
        colliding names across sets cannot shadow each other.
        """
        namespaces: dict[str, list[Path]] = {}

        if not self.rules_dir.exists():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return namespaces

        for subdir in sorted(self.rules_dir.iterdir()):
            if not subdir.is_dir():
                continue
            files = sorted(subdir.glob("*.yar")) + sorted(subdir.glob("*.yara"))
            if files:
                namespaces[subdir.name] = files

        root_files = sorted(self.rules_dir.glob("*.yar")) + sorted(
            self.rules_dir.glob("*.yara")
        )
        if root_files:
            namespaces["root"] = root_files

        return namespaces

    def compile_rules(self) -> None:
        """Compile every rule file, one namespace per rules subdirectory."""
        if not HAS_YARA:
            self._compile_error = "yara_x is not installed"
            return

        namespaces = self._find_rule_files()
        if not namespaces:
            self._compile_error = f"No rule files found under {self.rules_dir}"
            return

        compiler = yara_x.Compiler()
        total = 0

        for namespace, files in namespaces.items():
            compiler.new_namespace(namespace)
            for path in files:
                try:
                    compiler.add_source(path.read_text(encoding="utf-8"), origin=str(path))
                    total += 1
                except yara_x.CompileError as e:
                    self._compile_error = f"{path.name}: {e}"
                    logger.error("YARA-X compile error in %s: %s", path, e)
                    return

            self._rules_sources.append(f"{namespace} ({len(files)} files)")

        try:
            self._compiled = compiler.build()
        except yara_x.CompileError as e:
            self._compile_error = str(e)
            logger.error("YARA-X compilation failed: %s", e)
            return

        self._rules_loaded = total
        scanner = yara_x.Scanner(self._compiled)
        scanner.set_timeout(self.timeout_seconds)
        self._scanner = scanner
        self._compile_error = None

        logger.info(
            "Compiled %d YARA-X rule files from %d namespaces",
            total, len(namespaces),
        )

    # ------------------------------------------------------------------- scan

    def scan(self, file_path: Path) -> YARAResult:
        """Scan a file against all compiled rules."""
        if not HAS_YARA:
            return YARAResult(error="yara_x is not installed", rules_loaded=0)
        if not file_path.exists():
            return YARAResult(error=f"File not found: {file_path}")

        self._ensure_compiled()
        if self._scanner is None:
            return YARAResult(rules_loaded=0, error=self._compile_error or "No rules available")

        result = YARAResult(
            rules_loaded=self._rules_loaded,
            rules_sources=self._rules_sources,
        )
        start = time.monotonic()
        try:
            raw = self._scanner.scan_file(str(file_path))
            result.matches = self._parse_matches(raw)
        except yara_x.TimeoutError:
            result.error = f"YARA-X scan timed out after {self.timeout_seconds}s"
            logger.warning("YARA-X scan timed out for %s", file_path)
        except yara_x.ScanError as e:
            result.error = f"YARA-X scan error: {e}"
            logger.error("YARA-X scan failed for %s: %s", file_path, e)

        result.scan_time_ms = (time.monotonic() - start) * 1000
        logger.info(
            "YARA-X scan of %s: %d matches in %.1fms",
            file_path.name, len(result.matches), result.scan_time_ms,
        )
        return result

    def scan_bytes(self, data: bytes) -> YARAResult:
        """Scan in-memory bytes against all compiled rules."""
        if not HAS_YARA:
            return YARAResult(error="yara_x is not installed", rules_loaded=0)

        self._ensure_compiled()
        if self._scanner is None:
            return YARAResult(rules_loaded=0, error=self._compile_error or "No rules available")

        result = YARAResult(
            rules_loaded=self._rules_loaded,
            rules_sources=self._rules_sources,
        )
        start = time.monotonic()
        try:
            raw = self._scanner.scan(data)
            result.matches = self._parse_matches(raw)
        except yara_x.TimeoutError:
            result.error = f"YARA-X scan timed out after {self.timeout_seconds}s"
        except yara_x.ScanError as e:
            result.error = f"YARA-X scan error: {e}"

        result.scan_time_ms = (time.monotonic() - start) * 1000
        return result

    def _ensure_compiled(self) -> None:
        if self._scanner is None:
            self.compile_rules()

    @staticmethod
    def _parse_matches(scan_results: object) -> list[YARAMatch]:
        """Convert YARA-X ``ScanResults`` into ``YARAMatch`` objects."""
        matches: list[YARAMatch] = []
        for rule in getattr(scan_results, "matching_rules", []) or []:
            meta = {key: value for key, value in (getattr(rule, "metadata", ()) or ())}

            matched_strings: list[dict] = []
            for pattern in getattr(rule, "patterns", ()) or ():
                for hit in getattr(pattern, "matches", ()) or ():
                    matched_strings.append(
                        {
                            "identifier": getattr(pattern, "identifier", ""),
                            "offset": getattr(hit, "offset", 0),
                            "length": getattr(hit, "length", 0),
                            "xor_key": getattr(hit, "xor_key", None),
                        }
                    )

            matches.append(
                YARAMatch(
                    rule=getattr(rule, "identifier", ""),
                    namespace=getattr(rule, "namespace", "") or "",
                    tags=list(getattr(rule, "tags", ()) or []),
                    meta=meta,
                    matched_strings=matched_strings,
                )
            )
        return matches


# ---------------------------------------------------------------------------
# Rule linting — CI gate
# ---------------------------------------------------------------------------


@dataclass
class RuleLintReport:
    """Result of linting the rule sets."""

    rules_dir: Path
    files_checked: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    accepted_warnings: dict[str, str] = field(default_factory=dict)
    rules_without_attack_mapping: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "rules_dir": str(self.rules_dir),
            "files_checked": self.files_checked,
            "ok": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
            "accepted_warnings": self.accepted_warnings,
            "rules_without_attack_mapping": self.rules_without_attack_mapping,
        }


def _iter_rule_blocks(source: str) -> list[tuple[str, str]]:
    """Yield ``(rule_name, block_text)`` for every rule in a source string.

    Uses brace matching rather than a regex: rules are routinely written on a
    single line in tests and in small rule files, and a `\n}` anchor silently
    fails to find those, which would make the ATT&CK check vacuous.
    """
    blocks: list[tuple[str, str]] = []
    for match in re.finditer(r"\brule\s+(\w+)\s*\{", source):
        name = match.group(1)
        depth = 0
        index = match.end() - 1
        while index < len(source):
            char = source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    blocks.append((name, source[match.start(): index + 1]))
                    break
            index += 1
    return blocks


def lint_rules(rules_dir: Path = RULES_DIR) -> RuleLintReport:
    """Lint every rule file: compile cleanly, obey naming and metadata rules.

    Returns:
        A report whose ``errors`` should fail CI. Warnings are advisory.
    """
    report = RuleLintReport(rules_dir=rules_dir)

    if not HAS_YARA:
        report.errors.append("yara_x is not installed; cannot lint rules")
        return report

    if not rules_dir.exists():
        report.errors.append(f"Rules directory not found: {rules_dir}")
        return report

    files = sorted(rules_dir.rglob("*.yar")) + sorted(rules_dir.rglob("*.yara"))
    if not files:
        report.errors.append(f"No rule files found under {rules_dir}")
        return report

    for path in files:
        report.files_checked += 1
        source = path.read_text(encoding="utf-8")

        # error=True makes convention violations fail CI rather than scroll past.
        # A violation raises CompileError from add_source, which is the same
        # path a syntax error takes, so both end up reported as errors.
        compiler = yara_x.Compiler()
        compiler.allowed_rule_name(RULE_NAME_PATTERN, True)

        # yara_x 1.21 ships a .pyi whose `allowed_metadata` parameter order does
        # not match the runtime (runtime: required, error, regexp; stub: required,
        # regexp, error). Call through Any so the correct runtime order is used
        # without disabling type checking for the rest of this module.
        metadata_setter = cast(Any, compiler)
        for name in REQUIRED_METADATA:
            metadata_setter.allowed_metadata(name, yara_x.MetaType.STRING, True, True, None)

        try:
            compiler.add_source(source, origin=str(path))
        except yara_x.CompileError as e:
            report.errors.append(f"{path.name}: {e}")
            continue

        # Must be read BEFORE build(): build() resets the compiler and every
        # lint result silently becomes empty.
        for warning in compiler.warnings():
            title = str(warning.get("title", warning))
            key = f"{path.name}: {title}"
            if key in ACCEPTED_WARNINGS:
                report.accepted_warnings[key] = ACCEPTED_WARNINGS[key]
            else:
                report.warnings.append(key)
        for error in compiler.errors():
            report.errors.append(f"{path.name}: {error.get('title', error)}")

        try:
            compiler.build()
        except yara_x.CompileError as e:
            report.errors.append(f"{path.name}: {e}")
            continue

        # Advisory: every rule except test patterns should map to ATT&CK.
        for rule_name, block in _iter_rule_blocks(source):
            if any(tag in rule_name for tag in ATTACK_MAPPING_EXEMPT):
                continue
            if "mitre_attck" not in block:
                report.rules_without_attack_mapping.append(f"{path.name}: {rule_name}")

    if not report.ok:
        logger.error("Rule lint failed with %d error(s)", len(report.errors))
    else:
        logger.info(
            "Rule lint passed: %d files, %d unaccepted warning(s), %d accepted",
            report.files_checked, len(report.warnings), len(report.accepted_warnings),
        )

    return report
