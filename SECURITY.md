# Security Policy

## Reporting

Open a private security advisory on the repository, or contact the maintainer directly. Do not open a public issue for anything exploitable.

## What this project is, security-wise

HATCHERY **runs untrusted code**. That is its job. Treat every part of it accordingly.

The isolation boundary comes from the host, not from this code, and `hatchery doctor` reports which tier is in force. Tier 1 (`shared-kernel`, plain containers) is **not** a security boundary: the sample shares your kernel, and one kernel vulnerability reachable through an allowed syscall is enough. Run samples you do not trust only at tier 2 (gVisor) or tier 3 (microVM), on a machine you are willing to lose.

The seccomp profile in `engine/sandbox/seccomp.json` is a deny-list and is therefore **hardening, not isolation**. It must permit `ptrace`, because the sandbox observes behavior with `strace`; a profile that denies `ptrace` silently disables monitoring. `tests/test_seccomp.py` enforces that contract.

## Hardening checklist for operators

- [ ] Run at tier 2 or 3 for anything untrusted. Verify with `hatchery doctor`.
- [ ] Keep the sandbox network `internal` (the default). It has no route off the host.
- [ ] Set `HATCHERY_API_TOKEN`. Without it the API is unauthenticated and says so at startup.
- [ ] Keep `HATCHERY_HOST=127.0.0.1` unless you have a specific reason and a token set.
- [ ] Restrict `HATCHERY_ALLOWED_SAMPLE_ROOTS` to your real intake directory.
- [ ] Never point the API at a directory containing credentials or backups.
- [ ] Give the API's data directory the same care as the malware samples it stores: it holds live sample bytes and full behavioral traces.
- [ ] Cap resources: `ContainerConfig` sets `mem_limit`, `nano_cpus`, `pids_limit` and `no-new-privileges`. Do not remove them.
- [ ] Patch the host kernel regularly — at tier 1 the host kernel is the boundary.

## Security posture of the API

| Control | Default |
|:--|:--|
| Bind address | `127.0.0.1` |
| Authentication | off, with a startup warning; set `HATCHERY_API_TOKEN` |
| CORS | permissive (`origin: true`) — tighten before exposing |
| Sample path submissions | restricted to `samples/` and `uploads/` |
| Upload filenames | reduced to a bare name; traversal segments stripped |
| Artifact transfer | copy-based over the Docker API; tar members validated, `data` filter applied |
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
