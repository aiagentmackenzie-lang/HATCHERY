#!/usr/bin/env python3
"""Generate the pinned, compact MITRE ATT&CK Enterprise dataset.

HATCHERY maps observed behaviour to ATT&CK technique IDs. That mapping must be
checked against an authoritative dataset, and the dataset must be pinned so a
run is reproducible and a test can fail when the mapping drifts. Committing
MITRE's full STIX bundle (tens of megabytes) would be wasteful, so this script
derives a compact artifact from it and records, in the artifact header, the
source URL, the ATT&CK version string and the SHA256 of the source bytes.

Refresh (idempotent — a second run with the same source and output is a no-op):

    python scripts/refresh_attack_dataset.py                # fetch the pinned 19.2 URL
    python scripts/refresh_attack_dataset.py --input /tmp/enterprise-attack.json --version 19.2
    python scripts/refresh_attack_dataset.py --url <url> --version <v> --out engine/export/attack/dataset-<v>.json

The output artifact shape is consumed by ``engine.export.attack_dataset``:

    {
      "meta":      {framework, version, source_url, source_sha256, spec_version, ...},
      "techniques": {"T1059": {"name", "tactics", "is_subtechnique", "parent",
                               "is_revoked", "is_deprecated", "url",
                               "detection_strategy_ids": [...]}},
      "tactics":   {"stealth": "Stealth", ...}
    }
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ATTACK_DIR = REPO_ROOT / "engine" / "export" / "attack"

# The pinned source. `attack-stix-data` is MITRE's published STIX mirror; the
# versioned file is immutable, so this URL plus the recorded SHA256 is a
# reproducible pin.
PINNED_VERSION = "19.2"
PINNED_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{PINNED_VERSION}.json"
)


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hatchery-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=180) as resp:  # noqa: S310 - pinned MITRE URL
        return resp.read()


def _external_id(obj: dict, source_name: str = "mitre-attack") -> str:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return str(ref["external_id"])
    return ""


def derive(stix: dict) -> dict:
    objects = stix.get("objects") or []

    tactics: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            short = obj.get("x_mitre_shortname")
            if short:
                tactics[str(short)] = str(obj.get("name") or short)

    patterns = {
        obj["id"]: obj
        for obj in objects
        if obj.get("type") == "attack-pattern"
        and "enterprise-attack" in (obj.get("x_mitre_domains") or [])
    }

    # subtechnique-of relationships: child -> parent
    parent_of: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "subtechnique-of":
            parent_of[str(obj.get("source_ref"))] = str(obj.get("target_ref"))

    # detection strategy -> technique(s) it detects
    technique_detections: dict[str, list[str]] = defaultdict(list)
    strategy_ext_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-detection-strategy":
            eid = _external_id(obj)
            if eid:
                strategy_ext_id[str(obj["id"])] = eid
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "detects":
            target = str(obj.get("target_ref"))
            strategy = str(obj.get("source_ref"))
            eid = strategy_ext_id.get(strategy)
            if eid and target in patterns:
                technique_detections[target].append(eid)

    techniques: dict[str, dict] = {}
    for pattern_id, obj in patterns.items():
        tid = _external_id(obj)
        if not tid:
            continue
        parent = parent_of.get(pattern_id, "")
        parent_tid = _external_id(patterns[parent]) if parent in patterns else ""
        techniques[tid] = {
            "name": str(obj.get("name") or ""),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", []) or []],
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
            "parent": parent_tid,
            "is_revoked": bool(obj.get("revoked", False)),
            "is_deprecated": bool(obj.get("x_mitre_deprecated", False)),
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            "detection_strategy_ids": sorted(set(technique_detections.get(pattern_id, []))),
        }

    spec_version = ""
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            spec_version = str(obj.get("x_mitre_attack_spec_version") or "")
            break
    if not spec_version:
        for obj in patterns.values():
            spec_version = str(obj.get("x_mitre_attack_spec_version") or "")
            if spec_version:
                break

    return {
        "meta": {
            "framework": "MITRE ATT&CK Enterprise",
            "version": stix.get("x_mitre_version") or "",
            "spec_version": spec_version,
            "technique_count": len(techniques),
            "tactic_count": len(tactics),
            "detection_strategy_count": len(strategy_ext_id),
        },
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=PINNED_URL, help="ATT&CK STIX JSON URL")
    parser.add_argument("--input", type=Path, help="Use a local STIX file instead of fetching")
    parser.add_argument("--version", default=PINNED_VERSION, help="ATT&CK version string")
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output artifact path (default: engine/export/attack/dataset-<version>.json)",
    )
    parser.add_argument("--force", action="store_true", help="Rewrite even if the artifact is current")
    args = parser.parse_args(argv)

    out = args.out or (ATTACK_DIR / f"dataset-{args.version}.json")

    if args.input:
        raw = args.input.read_bytes()
        source_url = f"file://{args.input.resolve()}"
    else:
        raw = download(args.url)
        source_url = args.url

    sha256 = hashlib.sha256(raw).hexdigest()

    if out.exists() and not args.force:
        try:
            existing = json.loads(out.read_text())
            meta = existing.get("meta", {})
            if meta.get("source_sha256") == sha256 and meta.get("version") == args.version:
                print(f"up to date: {out} (ATT&CK {args.version}, sha256 {sha256[:16]}…)")
                return 0
        except json.JSONDecodeError:
            pass  # fall through and rewrite a corrupt artifact

    stix = json.loads(raw)
    derived = derive(stix)
    derived["meta"].update(
        {
            "version": args.version or derived["meta"]["version"],
            "source_url": source_url,
            "source_sha256": sha256,
            "generated_by": "scripts/refresh_attack_dataset.py",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(derived, separators=(",", ":"), sort_keys=False) + "\n", encoding="utf-8")
    size_kb = out.stat().st_size / 1024
    print(
        f"wrote {out} ({size_kb:.1f} KiB): "
        f"ATT&CK {derived['meta']['version']}, "
        f"{derived['meta']['technique_count']} techniques, "
        f"{derived['meta']['tactic_count']} tactics, "
        f"source sha256 {sha256}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
