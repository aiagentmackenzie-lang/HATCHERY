"""YARA rule scanning engine — match samples against curated rule sets.

Scans files against YARA rules from multiple sources:
- HATCHERY custom rules (anti-debug, sandbox evasion, packing detection)
- FLARE/Mandiant rules (APT-focused, high quality)
- MalwareBazaar community rules (broad coverage)

Falls back gracefully if yara-python is not installed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

try:
    import yara as yara_module
    HAS_YARA = True
except ImportError:
    HAS_YARA = False
    logger.warning("yara-python not available — YARA scanning disabled")

# Default rules directory (relative to this file)
RULES_DIR = Path(__file__).parent / "rules"


@dataclass
class YARAMatch:
    """A single YARA rule match."""
    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    matched_strings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "namespace": self.namespace,
            "tags": self.tags,
            "meta": self.meta,
            "matched_strings": self.matched_strings,
        }


@dataclass
class YARAResult:
    """Complete YARA scan result."""
    rules_loaded: int = 0
    rules_sources: list[str] = field(default_factory=list)
    matches: list[YARAMatch] = field(default_factory=list)
    scan_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "rules_loaded": self.rules_loaded,
            "rules_sources": self.rules_sources,
            "matches": [m.to_dict() for m in self.matches],
            "scan_time_ms": self.scan_time_ms,
            "error": self.error,
        }

    @property
    def has_matches(self) -> bool:
        return len(self.matches) > 0


class YARAScanner:
    """Scan files against YARA rules from multiple sources.

    Compiles rules from all available directories and scans files
    against them. Returns structured match results with metadata.
    """

    def __init__(self, rules_dir: Path = RULES_DIR) -> None:
        self.rules_dir = rules_dir
        self._compiled_rules: Optional[object] = None
        self._rules_loaded = 0
        self._rules_sources: list[str] = []

    def _find_rule_files(self) -> dict[str, list[str]]:
        """Find all .yar/.yara files in the rules directory.

        Returns:
            Dict mapping namespace name to list of file paths.
        """
        namespaces: dict[str, list[str]] = {}

        if not self.rules_dir.exists():
            logger.warning("Rules directory not found: %s", self.rules_dir)
            return namespaces

        for subdir in sorted(self.rules_dir.iterdir()):
            if subdir.is_dir():
                ns_files: list[str] = []
                for rule_file in sorted(subdir.rglob("*.yar")):
                    ns_files.append(str(rule_file))
                for rule_file in sorted(subdir.rglob("*.yara")):
                    ns_files.append(str(rule_file))
                if ns_files:
                    namespaces[subdir.name] = ns_files

        # Also check for root-level rules
        root_files: list[str] = []
        for rule_file in sorted(self.rules_dir.glob("*.yar")):
            root_files.append(str(rule_file))
        for rule_file in sorted(self.rules_dir.glob("*.yara")):
            root_files.append(str(rule_file))
        if root_files:
            namespaces["root"] = root_files

        return namespaces

    def compile_rules(self) -> None:
        """Compile all YARA rules from the rules directory.

        Called automatically before scanning if rules are not yet compiled.
        Handles syntax errors in individual files gracefully.
        """
        if not HAS_YARA:
            logger.warning("Cannot compile YARA rules — yara-python not available")
            return

        namespaces = self._find_rule_files()
        if not namespaces:
            logger.info("No YARA rules found in %s", self.rules_dir)
            return

        filepaths: dict[str, str] = {}
        total_files = 0

        for namespace, files in namespaces.items():
            for f in files:
                # Use the filename (without extension) as the key
                key = Path(f).stem
                # Avoid key collisions by adding namespace prefix
                unique_key = f"{namespace}_{key}" if key in filepaths else key
                filepaths[unique_key] = f
                total_files += 1

            self._rules_sources.append(f"{namespace} ({len(files)} rules)")

        if not filepaths:
            return

        try:
            self._compiled_rules = yara_module.compile(filepaths=filepaths)
            self._rules_loaded = total_files
            logger.info(
                "Compiled %d YARA rules from %d sources",
                total_files, len(namespaces),
            )
        except yara_module.Error as e:
            logger.error("YARA compilation error: %s", e)
            # Try to compile each file individually to find the bad one
            self._compile_individually(filepaths)

    def _compile_individually(self, filepaths: dict[str, str]) -> None:
        """Compile YARA files individually, skipping broken ones.

        Args:
            filepaths: Dict mapping identifiers to file paths.
        """
        valid_rules: list[object] = []
        loaded = 0

        for key, path in filepaths.items():
            try:
                rule = yara_module.compile(filepath=path)
                valid_rules.append(rule)
                loaded += 1
            except yara_module.Error as e:
                logger.warning("Skipping broken YARA rule %s: %s", path, e)

        if valid_rules:
            # Store the first valid rule set; we'll scan with each
            self._compiled_rules = valid_rules
            self._rules_loaded = loaded
            logger.info(
                "Compiled %d/%d YARA rules (individual mode)",
                loaded, len(filepaths),
            )

    def scan(self, file_path: Path) -> YARAResult:
        """Scan a file against all compiled YARA rules.

        Args:
            file_path: Path to the file to scan.

        Returns:
            YARAResult with all matches found.
        """
        import time

        if not HAS_YARA:
            return YARAResult(error="yara-python not available")

        if not file_path.exists():
            return YARAResult(error=f"File not found: {file_path}")

        # Compile rules if not yet done
        if self._compiled_rules is None:
            self.compile_rules()

        if self._compiled_rules is None:
            return YARAResult(
                rules_loaded=0,
                error="No YARA rules available to scan with",
            )

        result = YARAResult(
            rules_loaded=self._rules_loaded,
            rules_sources=self._rules_sources,
        )

        start = time.monotonic()

        try:
            # Handle list of individually compiled rules
            if isinstance(self._compiled_rules, list):
                all_matches: list[YARAMatch] = []
                for rule_set in self._compiled_rules:
                    matches = rule_set.match(str(file_path))
                    all_matches.extend(self._parse_matches(matches))
                result.matches = all_matches
            else:
                matches = self._compiled_rules.match(str(file_path))
                result.matches = self._parse_matches(matches)

        except yara_module.Error as e:
            result.error = f"YARA scan error: {e}"
            logger.error("YARA scan failed for %s: %s", file_path, e)

        elapsed = time.monotonic() - start
        result.scan_time_ms = elapsed * 1000

        logger.info(
            "YARA scan of %s: %d matches in %.1fms",
            file_path.name, len(result.matches), result.scan_time_ms,
        )
        return result

    def scan_bytes(self, data: bytes) -> YARAResult:
        """Scan in-memory bytes against YARA rules.

        Args:
            data: Bytes to scan.

        Returns:
            YARAResult with all matches found.
        """
        import time

        if not HAS_YARA:
            return YARAResult(error="yara-python not available")

        if self._compiled_rules is None:
            self.compile_rules()

        if self._compiled_rules is None:
            return YARAResult(error="No YARA rules available")

        result = YARAResult(
            rules_loaded=self._rules_loaded,
            rules_sources=self._rules_sources,
        )

        start = time.monotonic()

        try:
            if isinstance(self._compiled_rules, list):
                all_matches: list[YARAMatch] = []
                for rule_set in self._compiled_rules:
                    matches = rule_set.match(data=data)
                    all_matches.extend(self._parse_matches(matches))
                result.matches = all_matches
            else:
                matches = self._compiled_rules.match(data=data)
                result.matches = self._parse_matches(matches)

        except yara_module.Error as e:
            result.error = f"YARA scan error: {e}"

        elapsed = time.monotonic() - start
        result.scan_time_ms = elapsed * 1000
        return result

    def _parse_matches(self, matches: list) -> list[YARAMatch]:
        """Parse raw YARA match objects into YARAMatch dataclasses.

        Args:
            matches: List of yara.Match objects.

        Returns:
            List of structured YARAMatch results.
        """
        results: list[YARAMatch] = []

        for match in matches:
            matched_strings: list[dict] = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    matched_strings.append({
                        "identifier": string_match.identifier,
                        "offset": instance.offset,
                        "matched_data": instance.matched_data.hex() if instance.matched_data else "",
                        "length": instance.matched_length,
                    })

            results.append(YARAMatch(
                rule=match.rule,
                namespace=match.namespace or "",
                tags=list(match.tags) if match.tags else [],
                meta=dict(match.meta) if match.meta else {},
                matched_strings=matched_strings,
            ))

        return results