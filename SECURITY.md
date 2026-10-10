# Security Policy

## Reporting

Open a private security advisory on the repository, or contact the maintainer directly. Do not open a public issue for anything exploitable.

## What this project is, security-wise

HATCHERY **runs untrusted code**. That is its job. Treat every part of it accordingly.

The isolation boundary comes from the host, not from this code, and `hatchery doctor` reports which tier is in force. Tier 1 (`shared-kernel`, plain containers) is **not** a security boundary: the sample shares your kernel, and one kernel vulnerability reachable through an allowed syscall is enough. Run samples you do not trust only at tier 2 (gVisor) or tier 3 (microVM), on a machine you are willing to lose.

The seccomp profile in `engine/sandbox/seccomp.json` is a deny-list and is therefore **hardening, not isolation**. It must permit `ptrace`, because the sandbox observes behavior with `strace`; a profile that denies `ptrace` silently disables monitoring. `tests/test_seccomp.py` enforces that contract.

## Delivery-format intake

A delivery container is untrusted input that HATCHERY deliberately parses. `engine/intake/delivery.py` is bounded: depth 3, at most 64 children, 64 MiB per member, 256 MiB uncompressed, a 200:1 compression-ratio guard, and refusal of symlink/device and encrypted members. Member names are flattened under `results/<task_id>/delivery/`, so an archive cannot write outside it. Extraction never executes anything. ZIP/OOXML, tar/gzip/bzip2/xz, HTML/SVG, Windows shell links (LNK), ISO9660/IMG, PDF, legacy Office OLE/CFB compound files and RTF embedded objects are parsed. Formats that are detected but not extracted (7z, RAR, CAB) are reported as unsupported with a reason instead of being silently ignored. The LNK, ISO9660 and PDF parsers are exercised in tests against container bytes written by independent libraries (`pylnk3`, `pycdlib`, `pypdf`); the OLE/CFB parser against `olefile` (independent CFB reader) and `oletools` (independent MS-OVBA implementation); and the RTF parser against `oletools.rtfobj` (independent RTF OLE-object extractor). All are dev-only dependencies. The runtime parses untrusted input with the standard library alone.

The OLE/CFB parser (`engine/intake/ole.py`) is bounded in the same spirit: FAT and mini-FAT chains are followed with a visited set and a hop cap, directory entries are read up to a fixed ceiling, stream reads are capped, and MS-OVBA decompression stops and raises rather than allocating without limit. It never executes the compound file's contents; VBA macro streams are only decompressed to text for scanning, and `\x01Ole10Native` payloads are carved as data.

The RTF parser (`engine/intake/rtf.py`) is bounded the same way: the group scanner is a single pass with a depth cap and an object-count cap, embedded objects are size-capped, and `\bin` raw regions are skipped so binary data cannot confuse group tracking — a `\bin` length that overruns the file or is negative raises instead of being silently dropped. A decoded `Package` object is an OLE compound file and is handed to the OLE parser; nothing is executed.

## Emulation (Windows PE)

`engine/emulate/` drives **Mandiant Speakeasy 2.0.0b6** (MIT, a pre-release kept in the optional `.[emulation]` extra, never in `dev` or the pinned python-gate matrix) to extract configuration from a Windows PE. It is a **declared, containerized, fail-closed analysis stage — not an isolation boundary** (D21).

- **What runs where.** Speakeasy interprets the sample's x86/x64 instructions in Unicorn and emulates Windows APIs in Python; the sample's code **never executes natively**. The residual attack surface is the host parser/emulator handling hostile bytes (pefile, Speakeasy's loader, capstone, Unicorn's C) — a superset of HATCHERY's existing host-side parsing surface (YARA-X, the delivery parsers). That is why it is not a library call on the analyst's desktop.
- **Container stance.** Emulation runs in its own image (`hatchery-emulation:latest`) at the probed isolation tier, with `--network none`, a read-only sample, `no-new-privileges`, **all capabilities dropped**, a non-root user (`uid 1000`), `mem_limit`/`nano_cpus`/`pids_limit` caps and a wall-clock cap. Sample and report move over the Docker API through a **named volume** read by a short `runc` sidecar — never a host bind mount (D5). At tier 2 the gVisor rootfs overlay is in-memory, so `get_archive` on the container itself cannot see the report; the named volume is the working route.
- **Gated on a boundary.** With no container runtime, emulation is **unavailable and declared**, not run on the host. The off-by-default `--allow-host-emulation` escape hatch exists for a dedicated Linux analysis host and prints a loud warning every time; it bypasses the container and is unsupported.
- **Fail-closed.** APIs the emulator does not implement (`error.type == "unsupported_api"`), emulator detection and the absent real network are declared blind spots. A crash, a wall-clock/timeout, or an empty report is **INCONCLUSIVE**, never clean. The report records the emulator version and a hash of the parsed report schema.
- **capa_dynamic.** Static capa and YARA over the emulator's captured memory snapshots, bounded by region/byte caps. It is **not** a synthesized CAPE report; a Speakeasy→CAPE adapter is deliberately not built.
- **Events.** Emulated events are written to a separate `emulation-events.jsonl`, never merged into the native `events.jsonl` (D4).

The emulation tests `importorskip` Speakeasy; the pinned python-gate matrix stays free of the beta. One opt-in CI job (`emulation-gate`) installs the extra and runs them.

## AI triage (local model)

`engine/triage/` asks a **local** Ollama model for an advisory triage of a run. It is the one component that handles sample-derived text outside a container, and it is treated as such (D22).

- **The sample stays on the machine — checked twice.** The endpoint defaults to `http://127.0.0.1:11434`; a non-loopback host is refused unless `--allow-remote-model`. Separately, a **`:cloud` model is refused** unless `--allow-remote-model` is set, because a cloud model is reached through localhost but runs on a vendor's GPU. Both permissions are recorded in the run and printed as a loud warning when used.
- **Hostile input is handled as hostile input.** All sample-derived text (filenames, strings, paths, URLs, mutex names, emulated IOCs) is rendered inside an `<untrusted-sample-data>` boundary. The boundary markers are stripped from the text first, so a sample cannot close the block early; control characters are removed and whitespace collapsed, so a string cannot forge extra lines. The prompt forbids following instructions inside the boundary. The adversarial-string test is in CI.
- **No sample text is executed, and none is stored in the triage result.** The result records the model-output summary, findings and the grounding ids; the raw evidence block is not persisted.
- **Fail-closed.** No model, a timeout, an unparseable response, or any verdict that fails grounding is `INCONCLUSIVE`, never clean.
- **Model output is never trusted as ground truth.** Ollama's schema enforcement is not the validator; `engine.triage.contract` re-validates, and `engine.triage.grounding` drops any claim whose citation does not exist in the run.

## Threat-intelligence push

`hatchery push` sends the run's STIX bundle to MISP or OpenCTI. The API token is read from `--token` or the environment, is used only to build the request, and is never written to the result object, the log, or the `push-<target>.json` audit file. TLS verification is on by default; `--insecure` exists for self-signed lab instances and warns each time it is used. A push is fail-closed: a non-2xx response or a transport error is reported with the status and exits non-zero.

## Hardening checklist for operators

- [ ] Run at tier 2 or 3 for anything untrusted. Verify with `hatchery doctor`.
- [ ] Keep the sandbox network `internal` (the default). It has no route off the host.
- [ ] Set `HATCHERY_ADMIN_TOKEN`. Without it the API is unauthenticated and says so at startup. Give integrations a `HATCHERY_READ_TOKEN` (viewer) instead of the admin token.
- [ ] Read the audit log (`GET /api/audit`) after an incident — it records who did what, without storing the credential itself.
- [ ] Keep `HATCHERY_HOST=127.0.0.1` unless you have a specific reason and a token set.
- [ ] Restrict `HATCHERY_ALLOWED_SAMPLE_ROOTS` to your real intake directory.
- [ ] Never point the API at a directory containing credentials or backups.
- [ ] Give the API's data directory the same care as the malware samples it stores: it holds live sample bytes and full behavioral traces.
- [ ] Cap resources: `ContainerConfig` sets `mem_limit`, `nano_cpus`, `pids_limit` and `no-new-privileges`. Do not remove them.
- [ ] Patch the host kernel regularly — at tier 1 the host kernel is the boundary.
- [ ] If you use triage, keep it local. Do not pass `--allow-remote-model` unless you intend sample-derived text to leave the machine.

## Security posture of the API

| Control | Default |
|:--|:--|
| Bind address | `127.0.0.1` |
| Authentication | off, with a startup warning; set `HATCHERY_ADMIN_TOKEN` (full) and `HATCHERY_READ_TOKEN` (read-only). `HATCHERY_API_TOKEN` is still accepted as a back-compatible admin token |
| Authorization | per-request role: reads need `viewer`, state changes need `admin`, `GET /api/audit` needs `admin`. Tokens compared in constant time |
| Audit log | every answered request is recorded in `audit_log` (actor, role, authenticated, method, path minus query, status). No token, header, body or sample byte is stored. `GET /api/audit` is admin-only |
| CORS | permissive (`origin: true`) — tighten before exposing |
| Sample path submissions | restricted to `samples/` and `uploads/` |
| Upload filenames | reduced to a bare name; traversal segments stripped |
| Artifact transfer | copy-based over the Docker API; tar members validated, `data` filter applied. At tier 2, a named Docker volume read by a short `runc` sidecar — never a host bind mount |
| Sample execution | unprivileged (`setpriv` to uid 1000); tracers run privileged, the sample never does |

## Issues fixed in this revision

These were found in a 2026-10 audit of the project and are fixed here. They are listed so the class of defect is visible, not as a how-to.

| Class | Impact if unfixed |
|:--|:--|
| Unauthenticated API on all interfaces | Anyone on the network could submit samples and read stored artifacts |
| `filePath` accepted any absolute host path | Submission endpoint doubled as a reader for arbitrary local files (read a file's extracted strings from the report) |
| Multipart filename not sanitized | Path traversal on upload; arbitrary file write outside the upload directory |
| Two divergent STIX producers, one emitting invalid `type--<rowid>` identifiers | Downstream consumers reject or mis-key the bundle |
| Hardcoded absolute path to another project on the author's machine | Non-portable; disclosed the author's filesystem layout |
| Artifact tar streams written straight to `*.log`/`*.pcap` filenames | Artifacts were tar archives with misleading names; every parser downstream read garbage |
| `except Exception: pass` around artifact collection | A sandbox that silently returns nothing looked like a clean sample |

## Out of scope

- Malware you detonate. HATCHERY does not prevent a sample from harming the host at tier 1 and does not claim to.
- The contents of `results/` and `data/`. They are attacker-controlled by design.
