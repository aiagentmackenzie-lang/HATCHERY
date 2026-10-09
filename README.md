# HATCHERY — Malware Sandbox Engine

> *Watch it hatch. Watch it burn. Either way, you'll know exactly what it did — and exactly what it couldn't tell you.*

Docker-hosted malware analysis for **Linux ELF samples**: static analysis, detonation under syscall tracing, filesystem and network capture, IOC extraction, MITRE ATT&CK mapping, and a result bundle designed to be ingested rather than admired.

---

## Read this first

HATCHERY probes the host and reports, **per run**, what isolation was actually in force. It also reports what the run could *not* establish. Both are stored in the result bundle and printed at the end of every analysis.

```
What this run does NOT establish:
  - Isolation tier 1 (shared-kernel): The sample shares the host kernel. Namespaces,
    cgroups and seccomp narrow what it may ask for; they do not stop a kernel exploit.
  - No hardware boundary was in force. An attacker would need to defeat only: a single
    kernel vulnerability reachable through an allowed syscall.
  - Network egress was blocked. Command-and-control contact, payload downloads and
    exfiltration cannot appear in this run by construction.
  - Dynamic analysis covers Linux ELF behavior only. Windows, macOS, document and script
    samples are analyzed statically; see the static section.
```

A sandbox that returns a verdict without its own caveats is the thing this project exists not to be. See [`docs/DECISIONS.md`](docs/DECISIONS.md) for why.

### Isolation tiers

The host decides the isolation; HATCHERY reports it honestly.

| Tier | Name | Boundary? | What an attacker must defeat | Host requirement |
|:--:|:--|:--:|:--|:--|
| 0 | `static-only` | ❌ | nothing executes | none |
| 1 | `shared-kernel` | ❌ | **one kernel bug reachable through an allowed syscall** | any Docker host |
| 2 | `sandboxed-kernel` (gVisor/`runsc`) | ✅ | a bug in a user-space kernel plus a usable host syscall | Linux, no KVM needed |
| 3 | `hardware-vm` (Kata/Firecracker) | ✅ | escape the guest kernel, then KVM, then the device model | Linux with `/dev/kvm` |

`hatchery doctor` prints this table with live capability detection. **Tier 1 is not a security boundary** and HATCHERY says so on every tier-1 run, in the terminal, the report and the API. The 2026 empirical basis: a kernel 0-day run against a container configured with seccomp on, an unprivileged uid and a patched kernel reached root in under two seconds; the same exploit against a microVM configured *worse* succeeded inside the guest and never reached the host.

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

hatchery doctor          # what isolation can this host actually give you?
hatchery build           # build the sandbox image
hatchery submit sample.elf --timeout 120
```

Output lands in `results/<task_id>/`:

```
results/<task_id>/
├── bundle/
│   ├── analysis.json     # the whole analysis document, incl. limitations
│   └── events.jsonl      # one normalized behavioral event per line
├── sandbox/
│   ├── strace/strace.log
│   ├── inotify/inotify.log
│   ├── tcpdump/capture.pcap
│   ├── exec/exec.log
│   └── dropped/
├── delivery/            # children extracted from a delivery container, if any
├── report.md             # human-readable
├── attack-navigator.json # ATT&CK Navigator Layer v4.5
├── ocsf.json             # OCSF 1.9.0 Detection Findings
└── stix_bundle.json      # STIX 2.1
```

The two files in `bundle/` are the source of truth. The API ingests them; the dashboard renders them; the Markdown report is generated from the same data.

---

## Capability matrix

Not aspirational. What is in the code today.

| Capability | Status | Notes |
|:--|:--:|:--|
| Hash (MD5/SHA1/SHA256), string extraction, PE/ELF parsing | ✅ | |
| YARA-X scanning | ✅ | Rust engine; YARA 4 is in maintenance mode upstream |
| Rule lint gate (`hatchery rules lint`) | ✅ | naming + required metadata are CI errors, not warnings |
| capa capability extraction | ✅ | static only (capa 9.x) |
| Packer detection | ✅ | UPX, VMProtect, Themida, MPRESS, NSIS, generic |
| Detonation under syscall tracing | ✅ | Linux ELF; artifact recovery verified end-to-end |
| **Per-tier monitoring strategy** | ✅ | every bundle names the collector used *and its blind spots*; a downgrade says so |
| **Evasion detection (scored, first-class)** | ✅ | recon breadth + ordering; a recon-then-quiet run is reported evasive/inconclusive |
| **gVisor tier-2 runtime + Sentry collector** | ✅ | per-container OCI annotations enable runsc's Sentry trace; the engine reads it back and emits `source="gvisor-sentry"` events |
| **eBPF syscall collection** | ❌ | intended for tier 3; tier 1 uses `strace` and **tier 2 uses gVisor's Sentry trace** |
| Filesystem monitoring (inotify) | ✅ | |
| Network capture (tcpdump → PCAP) | ✅ | parsed; **egress is blocked**, so this is usually empty by design |
| Dropped-file recovery | ✅ | filesystem diff, excludes its own working directory |
| IOC extraction + STIX 2.1 export | ✅ | one implementation; IDs validated against the spec |
| MITRE ATT&CK mapping | ✅ | data-driven from a pinned ATT&CK **19.2** dataset; unknown, revoked or wrong-tactic IDs fail a test |
| ATT&CK Navigator layer (v4.5) | ✅ | `attack-navigator.json`; score, colour and comment per technique |
| OCSF Detection Findings (1.9.0) | ✅ | `ocsf.json`; required fields and enum values validated against the pinned schema |
| Isolation tier probing + honest reporting | ✅ | the point of the project |
| `hatchery doctor` readiness check | ✅ | |
| API + dashboard backed by real data | ✅ | ingest verified: 572 events, 206 file, 32 network from one run |
| Result bundle consumed by the API | ✅ | single producer per table |
| **GHOSTWIRE C2 integration** | ❌ | package-name collision with HATCHERY's own `engine`; opt-in and non-functional |
| **Fake internet (DNS/HTTP/SMTP)** | ❌ | implemented but never started, and it would bind on the host. Removed from the claims until it is real. |
| **Windows / macOS dynamic analysis** | ❌ | static only |
| **Delivery-format intake (ZIP/OOXML, tar/gzip/bzip2/xz, HTML/SVG, LNK, ISO9660/IMG, PDF)** | ⚠️ | one bounded intake path; containers are unpacked and their children analysed statically. LNK and ISO9660 are fully parsed; PDF is targeted (embedded files + JavaScript). OLE/CFB, RTF, 7z, RAR and CAB are *detected and reported as unsupported* with a reason — never silently skipped |
| **Unpacking / config extraction (emulation)** | ❌ | planned; Speakeasy/Qiling for Windows PE config on a Linux host (D9) |
| **AI triage** | ❌ | planned; prompt-contract design is in the roadmap |
| **Candidate Sigma rules** | ⚠️ | generated drafts from observed behaviour; labelled as requiring review, never claimed validated |

---

## Known limitations (structural, not bugs)

1. **The Linux-only guest cannot hide its host.** KVM/CPU count/RAM/uptime are readable through `/proc` at any tier. No amount of environment faking fixes this; only a VM with a real guest kernel helps, and even then CPUID reports the hypervisor.
2. **Containers share a kernel.** At tier 1 there is no boundary. Run malware you do not trust only at tier 2 or 3, on a machine you are willing to lose.
3. **Egress is blocked by default.** The sandbox network is `internal`, so a sample cannot reach its real C2 or exfiltrate. The cost is that samples requiring a live internet will not fully detonate. A believable simulated internet is future work.
4. **Windows malware is analyzed statically.** Dynamic Windows analysis needs a Windows guest, which needs licensing and hardware virtualisation.
5. **`strace` is the tier-1 fallback, not the ambition.** ptrace-based tracing has high overhead and is detectable; in 2026 eBPF rootkits exist that `SIGKILL` processes which attempt to `ptrace` a protected PID. Tier 2 no longer uses ptrace: it reads gVisor's own Sentry trace from the runsc debug log. eBPF-based collection for tier 3 is the intended direction — see [`docs/DECISIONS.md`](docs/DECISIONS.md) D2, D11, D14.
6. **What each collector cannot see.** At tier 1, `strace` cannot see time-based checks: `RDTSC`, `CPUID` and vDSO-served `clock_gettime` are CPU/userspace operations, not syscalls (the probe in `tests/fixtures/strace-evasive-real.log` ran a `date +%s` loop and produced no clock syscall). At tier 2, gVisor's Sentry trace *does* capture `clock_gettime` — the vDSO path becomes a Sentry syscall — but `RDTSC`/`CPUID` remain instructions and are not emitted. Every run names its collector and that collector's blind spots, and reads `summary.evasion_*` from whatever source it actually had.
7. **Tier 2 was verified end-to-end on this host.** gVisor needs no KVM and the registration script exists; installing `runsc` and wiring its Sentry trace were verified against a real detonation. Two consequences are documented rather than hidden: gVisor's trace is container-wide, so the engine attributes events to the sample's process subtree and records how many entrypoint/monitor events it excluded; and Docker's `get_archive` cannot see files written inside a gVisor container because the rootfs overlay is in-memory, so the in-guest strace/inotify/dropped artifacts are recovered copy-based through a named Docker volume read back by a short `runc` sidecar — no host bind mount (D5). The Sentry trace remains the syscall collector.
8. **Delivery-format coverage is partial, and says which part.** A ZIP/OOXML package, a tar/gzip/bzip2/xz archive, an HTML/SVG page, a Windows shell link (LNK), an ISO9660/IMG image, or a PDF is unpacked on one bounded path and each extracted child is hashed, classified and run through YARA/strings/packer detection. LNK target/arguments/working-directory/icon fields and ISO9660 (incl. Joliet) directory trees are fully parsed; PDF is targeted at embedded files and JavaScript rather than a full object-graph parse. Extracted children are **not detonated**, and the run states that. Formats that are detected but not extracted in this revision — OLE/CFB legacy Office, RTF, 7z, RAR, CAB — are listed as unsupported with a reason, so a document is never an empty result. Extraction is bounded (depth, child count, per-entry and total size, compression ratio, symlink/device refusal, path-traversal confinement); hitting a bound is recorded, not hidden.

---

## CLI

```
hatchery doctor                     Host readiness: isolation tiers, image, rules
hatchery build                      Build the sandbox image
hatchery submit <file>              Static + dynamic analysis
hatchery static <file>              Static analysis only
hatchery status <task_id>           Task status
hatchery report <task_id>           Print a completed report
hatchery iocs <task_id>             IOC summary
hatchery rules lint                 Lint the YARA rules (exits 1 on error)
```

Options for `submit`: `--timeout SECONDS`, `--output/-o DIR`, `--no-sandbox`.

---

## API

```bash
cd server && npm install && npm run build && npm start   # http://127.0.0.1:3002
cd dashboard && npm install && npm run dev                # http://localhost:5173
```

| Method | Endpoint | Description |
|:--|:--|:--|
| POST | `/api/submit` | Submit a sample (JSON `filePath`, or multipart upload) |
| POST | `/api/submit/:id/retry` | Re-analyze an existing task |
| GET | `/api/tasks` | List tasks |
| GET | `/api/tasks/:id` | Task + static + sandbox results + IOC/event summaries |
| GET | `/api/tasks/:id/events` | Behavioral events (paginated, filterable) |
| GET | `/api/tasks/:id/network` | Network connections |
| GET | `/api/tasks/:id/filesystem` | Filesystem events |
| GET | `/api/tasks/:id/report` | Full report (json/markdown) |
| GET | `/api/tasks/:id/iocs` | IOCs (json/stix/text) |
| WS | `/ws` | Real-time event stream |

**Security defaults.** Binds `127.0.0.1`. Set `HATCHERY_API_TOKEN` to require `Authorization: Bearer <token>`; without it the API is unauthenticated and logs a warning at startup. `filePath` submissions are restricted to `samples/` and `uploads/` (override with `HATCHERY_ALLOWED_SAMPLE_ROOTS`), and uploaded filenames are reduced to a bare name. See [`SECURITY.md`](SECURITY.md).

---

## Development

```bash
ruff check engine/ tests/ && mypy engine/ && pytest -q      # 390 tests
hatchery rules lint                                          # YARA gate
HATCHERY_E2E=1 pytest tests/test_dynamic_e2e.py -v            # really detonates (needs Docker)
```

The pinned frameworks are refreshed with one idempotent script, which records the
source URL, version string and SHA256 in the generated artifact:

```bash
python scripts/refresh_attack_dataset.py
```

The end-to-end suite is opt-in because it starts a container. It is the suite that would have caught every blocker this project shipped with: it asserts that syscalls are really captured, filesystem events are really recorded, artifacts are really recovered, the sample's own exit code is reported, and the bundle really describes the run.

---

## Architecture

```
sample ──► intake (hash / delivery unpack / PE / ELF / strings)
              │
              ├──► static (YARA-X / capa / packer) ───┐
              │                                       │
              └──► detonation (tier-probed container) │
                        │  collector (strace / gVisor  │
                        │  Sentry trace / host eBPF)    │
                        │      └──► events.jsonl        │
                        │  inotify ──► events.jsonl     ├──► bundle/analysis.json
                        │  tcpdump ──► pcap ────────────┘    bundle/events.jsonl
                        │                                   │
                        └──► artifacts ──► run dir          ├──► report.md
                                                           ├──► stix_bundle.json
                                                           └──► API ingest ──► SQLite ──► dashboard
```

---

## Roadmap

**Phase 0 — make it true.** ✅ *done in this revision.* Ten ship-blockers fixed (network never created, artifact paths wrong, seccomp blocking its own tracer, unbound name masking errors, exit code always zero, fake services never started, no ingest path so the dashboard was permanently empty, and more), the README rewritten to match reality, and the security defaults tightened.

**Phase 1 — an isolation boundary that holds.** ✅ *evasion instrumented as a first-class scored signal; a per-tier monitoring strategy named in every run; and the gVisor tier-2 boundary made real and wired — a runsc runtime, per-container OCI annotations that enable the Sentry trace, and a parser that turns it into `source="gvisor-sentry"` events and evasion scores. Verified end-to-end on a live gVisor detonation.* ⚠️ *host-side eBPF for tier 3 is designed and declared per run but not wired; `strace` remains the tier-3 fallback and the run says so.*

**Phase 2 — breadth.** Delivery-format intake is **largely done in this revision**: ZIP/OOXML Office, tar/gzip/bzip2/xz, HTML/SVG, Windows shell links (LNK), ISO9660/IMG images and PDF embedded files/JavaScript are unpacked on one bounded intake path and each extracted child is hashed, classified and analysed statically, while OLE/CFB legacy Office, RTF, 7z, RAR and CAB are detected and reported as unsupported (never silently skipped) — see D19. Emulation-based unpacking/config extraction and extraction of those remaining formats are still ahead. The telemetry half is **done**: the ATT&CK mapping is rebuilt data-driven from a pinned **ATT&CK 19.2** dataset (the `Stealth`/`Impair Defenses` split, Detection Strategies and revoked-ID validation included), the bundle emits **OCSF 1.9.0 Detection Findings** and an **ATT&CK Navigator Layer v4.5**, tier-2 traces are attributed to the sample's process subtree, tier-2 in-guest artifacts are recovered copy-based, and candidate **Sigma rules** are emitted as generated drafts. MISP/OpenCTI push remains planned.

**Phase 3 — AI triage, done properly.** Local (Ollama) function-level behavioral reporting with versioned prompt contracts, JSON-schema-validated output, grounding requirements and **fail-closed suppression**. Sample-derived text is treated as hostile input: malware contains strings designed to steer an LLM's verdict.

**Phase 4 — product.** Queue and workers, RBAC and audit log, sample store with TTL, reproducible runs.

---

## Sources for the design decisions

CAPEv2, Joe Sandbox v44 (2026), VMRay, Firecracker and gVisor design docs, Kata Containers, Dirty Frag container-vs-microVM evaluation (2026), Datadog Security Labs on eBPF rootkits (2026), YARA-X 1.0 release and VirusTotal's migration, mandiant/capa v9.x releases, MITRE ATT&CK v18/v19 release notes, NIST SP 800-61r3 (2025), Microsoft Research Project Ire (2026), VirusTotal Code Insight, and the Microsoft DTDA paper on production LLM prompt contracts. Full citations are in [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

*Built by Raphael Main + Agent Mackenzie.*
