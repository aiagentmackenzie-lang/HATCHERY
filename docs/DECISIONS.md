# Design Decisions

A record of the decisions that shaped this revision, with the evidence behind them. Dates are 2026-10-09 unless noted.

---

## Why this document exists

The April 2026 revision of HATCHERY was built on two design decisions that were reasonable at the time and are wrong now:

1. *"Docker over VM — speed versus isolation; we accept weaker isolation."*
2. *"strace over API hooking — harder to detect, no in-guest agent."*

Both were revisited against 2026 evidence. The project was also found to have ten ship-blockers that made its dynamic path unable to run at all, and a dashboard that had never received a row of data. Deciding to fix the architecture without fixing the spine would have been pointless, so Phase 0 is "make it true" and everything else follows.

---

## D1 — Isolation is a property of the host, and the tool must say which tier is in force

**Decision.** Replace the fixed "Docker container" assumption with a probed isolation tier model (`STATIC_ONLY` → `SHARED_KERNEL` → `SANDBOXED_KERNEL` → `HARDWARE_VM`). Every run records the tier, the boundary in force, and what an attacker would have to defeat. Tier 1 is labeled "not a security boundary" in the terminal, the report and the API.

**Evidence.**
- A 2026 kernel 0-day evaluation ("Dirty Frag") ran the same exploit against both models. Container, configured carefully (Docker, seccomp on, unprivileged `uid=1001`, patched kernel 6.8.0): **unprivileged user to root in under 2 seconds.** MicroVM, configured deliberately *worse* (unpatched guest kernel, no seccomp, running as root, full capabilities): the exploit worked inside the guest and **every attempt to reach the host failed**. The conclusion circulating in the industry: *"What matters isn't what permissions the software grants — it's whether the kernel is shared."*
- The speed argument for containers is gone. Firecracker: **<125 ms** boot to userspace, **<5 MiB** overhead per microVM, up to **150/s per host**, **5–30 ms** from golden-snapshot restore. gVisor's `systrap` platform removed most of the old syscall overhead cliff.
- Production deployments have already split this way: AWS Lambda and Vercel Sandbox run Firecracker; Google Cloud Run, GKE Sandbox, App Engine, **OpenAI** and **Anthropic's claude.ai code execution** run gVisor; Modal runs gVisor; Fly.io runs Firecracker with an egress allow-list.

**Consequence.** A container-based run is still supported and still useful — it is fast, it works on any Docker host including macOS, and it is genuinely adequate for first-pass triage of samples you already believe are benign. It is no longer described as isolation.

**Trade-off accepted.** Supporting all four tiers is more code than supporting one. The alternative is a tool that either lies about its guarantees or refuses to run on the machine its author actually has.

---

## D2 — Keep `strace`, but demote it to a declared fallback; eBPF is the intended direction

**Decision.** `strace` remains the tracer for tier 1, where it is the only option, and its limitations are stated in the README. The seccomp profile **must** permit `ptrace`, and a test enforces it. eBPF collection is Phase 1 work.

**Evidence.**
- ptrace-based tracing stops the traced process at every syscall entry and exit and context-switches to the tracer. Independent benchmarking of syscall tracing at a 1.19M calls/s baseline: VMI-based tracing dropped to **0.48%** of baseline, eBPF held **31%** — a 20–100× difference. ptrace requires per-process attach and is *"trivially detectable by the target."*
- Worse, it is now actively attacked. The **Atomic Arch** campaign's eBPF rootkit attaches to `tp/syscalls/sys_enter_ptrace` and calls `bpf_send_signal(SIGKILL)` **on the process that tries to ptrace a protected PID**. A sample can kill the tracer rather than merely notice it. **VoidLink** and **LinkPro** similarly manipulate `bpf_probe_write_user()`, `bpf_override_return()` and process hiding.
- Falco (CNCF graduated), Tetragon and Tracee are the production-standard eBPF runtimes.

**Why not switch now.** eBPF needs a Linux host with BPF and BTF; on macOS and on this project's own CI there is no host to attach to. Fixing the fallback first — which was not merely suboptimal but *non-functional*, see D4 — was the correct order.

**Consequence.** `engine/sandbox/seccomp.json` no longer denies `ptrace`. The previous profile denied the exact syscall its own monitoring depended on, so the isolation profile silently disabled the product. That denial is now a test failure.

---

## D3 — Report limitations per run; never return a bare verdict

**Decision.** Every analysis carries a `limitations` list, computed from what actually happened, and it is printed, stored in the bundle, written into the Markdown report and exposed by the API.

**Evidence.**
- The failure mode is well documented: *"A clean sandbox verdict means the file did nothing observable in that environment during that window. For an evasive sample, those are the exact conditions it was built to survive."* Sandbox evasion re-entered Palo Alto's Red Report 2026 top 10 after two years absent.
- Microsoft's production DTDA agent uses **fail-closed suppression**: invalid output suppresses the alert rather than emitting an unsupported one. HATCHERY applies the same posture to its own conclusions.

**Consequence.** A run that produced no events is labeled `INCONCLUSIVE`, not clean. A tier-1 run states that no hardware boundary was in force. An egress-blocked run states that C2 behaviour cannot appear by construction. `summary.inconclusive` is a boolean, not a judgment call by the reader.

---

## D4 — One producer per data path

**Decision.** The engine writes `bundle/analysis.json` + `bundle/events.jsonl`. The API ingests them into SQLite. There is exactly one writer per table and exactly one STIX implementation.

**Evidence (measured, not theorized).**
- Grepping `server/` for `INSERT INTO` returned **exactly one hit**: the `tasks` row. `static_results`, `sandbox_results`, `behavioral_events` and `iocs` were never written by any code path. Every dashboard panel read four permanently empty tables. The Live Timeline, Process Tree, Network Panel, Filesystem View and IOC Panel could not ever have shown data.
- The two halves were connected by a `spawn()` and nothing else: the Python engine wrote files, the TypeScript server read SQLite, no adapter existed.
- STIX had **two divergent producers**. The Python exporter generated spec-conformant `indicator--<uuid5>` IDs; the TypeScript route generated `indicator--<sqlite row id>` and `identity--<taskId>`, neither of which is a legal STIX 2.1 identifier. The API now serves the Python bundle and the duplicate implementation is deleted.

**Verified after the fix.** One run of a benign probe script through the API produced: 572 behavioural events (file 206, memory 138, network 32, process 14, system 182), 5 IOCs, 32 network connections, 206 filesystem events, and a populated `sandbox_results` row — all served by the API.

---

## D5 — Copy artifacts out; do not bind-mount the analysis directory

**Decision.** Sample and artifacts move over the Docker API (`put_archive` / `get_archive`), with tar members validated and extracted using the `data` filter.

**Evidence.**
- A bind mount assumes the Docker daemon can see a path on *this* machine, which breaks for remote daemons, Docker-in-Docker and microVM-backed runtimes. `get_archive` works everywhere.
- The previous implementation wrote the raw `get_archive` stream to `strace.log`. `get_archive` returns a **tar archive**, so every "log" and "pcap" on disk was a tar file with a misleading name. Verified against a real run.

---

## D6 — Fix the test suite's relationship with reality

**Decision.** Add a fixture captured from a real run, and assert against it.

**Evidence.** `tests/test_strace_parser.py` asserted lines formatted `TIMESTAMP PID syscall(...)`. Real `strace -f -tt` output to a file is `PID TIMESTAMP syscall(...)`. The parser matched **0 of 227 lines** of genuine output while its tests passed, because the tests encoded the author's assumption rather than observed output. `tests/fixtures/strace-real.log` is a real capture with the field order documented, and `tests/test_strace_real_format.py` fails if the parser stops matching it.

The same class of defect appeared three more times: a report test asserted a section rendered from `sandbox_results["strace"]["network_connections"]`, a key no producer ever wrote; the end-to-end path had no test at all; and `npm run build` output was never started, because `tsc` does not copy `schema.sql`.

**Consequence.** The end-to-end suite (`HATCHERY_E2E=1`) now asserts that syscalls are really captured, filesystem events are really recorded, artifacts are really recovered and the sample's own exit code is reported.

---

## D7 — YARA-X, and rules are linted in CI

**Decision.** Migrate from `yara-python` to `yara_x`, and add `hatchery rules lint` as a CI gate where naming and required metadata are **errors**.

**Evidence.** YARA-X shipped **1.0.0 stable in June 2025**; the original YARA is officially in **maintenance mode** — no new features, no new modules. VirusTotal runs YARA-X in production for Livehunt and Retrohunt. It is written in Rust, which matters because it parses hostile binaries, and it is 5–10× faster on the complex-regex rules that dominate scan time. It also provides compiler lints, which the previous setup had no equivalent of.

**What the gate found immediately on this repository's own rules:** a **deprecated `pe.number_of_sections` field** that will break on a future YARA-X release, an unbounded quantifier flagged as a slow pattern, two hex patterns that are cheaper as text literals, and a rule with no ATT&CK mapping. All fixed.

**API note for maintainers.** `Compiler.build()` resets the compiler, so `errors()` and `warnings()` must be read *before* `build()`. Reading them afterwards returns empty lists and silently disables every lint.

---

## D8 — Tighten the API's defaults

**Decision.** Bind `127.0.0.1` by default. Support `HATCHERY_API_TOKEN`. Restrict `filePath` submissions to configured roots. Reduce uploaded filenames to a bare name. Warn loudly when unauthenticated.

**Evidence.** The API accepted an absolute `filePath` for any host file and returned its extracted strings in the report — a local file-read primitive in a security tool. Multipart filenames were joined into the upload directory unsanitized, giving path traversal on write. CORS was `origin: true` on `0.0.0.0`. A product that stores live malware samples and full behavioral traces needs sane defaults.

**Not done, deliberately.** A required token by default would break the local dashboard workflow this project is used with. Instead the default is loopback-only plus a startup warning naming the risk. That is a judgment call, and it is written down here so it can be revisited.

---

## D9 — No Windows guest, no fake Windows profile

**Decision.** The guest is a consistent **Linux workstation**. The faked `DESKTOP-WIN10` hostname, `C:\` environment variables and `/usr/bin/vmtoolsd → /bin/true` stubs are removed. Windows samples are analyzed statically.

**Evidence.** Faking Windows artifacts inside a Linux kernel is worse than faking nothing: the sample sees `KVMKVMKVM` from CPUID leaf `0x40000000`, a Linux kernel and a Linux `/proc`, while its environment claims to be Windows. Inconsistency is itself a signal, and modern loaders chain a dozen checks in random order — `CPUID` hypervisor bit and vendor leaf, core count, RAM, disk size, uptime, username blacklists, recent-document counts, cursor movement, window counts, domain-join state — and abandon execution at the first failure.

A real Windows guest needs licensing, KVM and a much larger operational surface. It is the single biggest scope decision in the project and it was deferred rather than faked.

**Future path.** Emulation-based analysis (Speakeasy/Qiling) can extract configuration and resolve APIs from Windows PE samples on a Linux host without a Windows guest. That is the intended next step for Windows coverage, followed by a real guest if warranted.

---

## D10 — Egress blocked by default; "fake internet" removed from the claims

**Decision.** The sandbox network is `internal` with no route off the host. The DNS/HTTP/SMTP fake services are documented as **not functional** and the README claim is removed.

**Evidence.**
- Letting a sandbox phone home from an analyst's workstation is worse than blocking it.
- The INetSim-style "answer everything" approach is itself a fingerprint: a network where every query resolves and every port answers does not resemble the real internet, which NXDOMAINs, RSTs and blackholes. Joe Sandbox v44 added SOCKS/HTTP proxy support precisely because phishing infrastructure bot-scores datacenter IPs and serves decoys to them instead of payloads.
- The services were never started by any code path, and would have bound `0.0.0.0` on the host.

**Cost accepted.** Samples that require a live internet will not fully detonate, and this is stated in every run's limitations.

---

## D11 — The monitoring strategy is per-tier, and every run names the collector it used

**Decision.** Observation is separated from isolation. The tier decides what an attacker must defeat; the *collector* decides what was actually observed, and it changes with the tier:

| Tier | Collector | Location |
|:--|:--|:--|
| 1 shared-kernel | `strace-ptrace` | in-guest (attached to the sample) |
| 2 sandboxed-kernel | `gvisor-sentry-strace` | host (runsc's own Sentry trace) |
| 3 hardware-vm | `ebpf-host` | host (eBPF past the guest) |

Every bundle records `sandbox.monitoring` — collector, location, and its blind spots — and `compute_limitations` turns that into a plain-language line. When the recommended collector for a tier is not implemented yet, `resolve_collector()` returns the fallback **and a downgrade reason**, and that reason is printed, stored and rendered. A run may never imply a stronger collector than it used.

**Evidence — `strace` cannot see the checks that matter most.** The captured fixture `tests/fixtures/strace-evasive-real.log` ran `date +%s` inside a five-iteration timing loop. The strace log contains **no clock syscall at all**: glibc served `clock_gettime` from the vDSO, which is a pure userspace call. `RDTSC` and `CPUID` are CPU instructions and are never syscalls to begin with. A ptrace-based tracer therefore cannot see most accelerated-sleep and time-based-evasion checks — the exact thing D9 names as the load-bearing check. `tests/test_evasion.py::test_vdso_clock_reads_are_invisible_to_strace` pins this observation.

**What is not wired, and is said so.** At tiers 2 and 3 the run still falls back to ptrace today. gVisor exposes its own Sentry trace (`runsc --strace`), and its `strace`/`strace-syscalls`/`strace-log-size` flags are in gVisor's OCI-annotation override allow-list, but the trace destination (`--debug-log`) is a host-side runtimeArg and reading it back into the bundle is future work. `scripts/install-runsc-docker-runtime.sh` registers a runtime with the trace on; the engine does not yet collect from it, and the report says so rather than pretending.

---

## D12 — Evasion is a first-class, scored signal; recon-then-quiet is inconclusive

**Decision.** `engine/monitor/evasion.py` scores *density and ordering* of environment reconnaissance, emits `category="evasion"` events into the same `events.jsonl` stream, and writes `summary.evasion_score` / `summary.evasive` / `summary.evasion_inconclusive` into the bundle. A run that reconnoiters across several categories and then exits without observable impact is reported as **evasive and INCONCLUSIVE**, with an explicit line in `limitations`.

Signals scored: VM/DMI artifact reads, VM-guest-tool paths, `/proc/cpuinfo`/`auxv`, `/proc/uptime`, `/proc/self/status` (TracerPid) and `ptrace`, `/proc/self/maps`, analysis-tool enumeration, repeated `nanosleep`/`clock_nanosleep`, and the recon→quiet ordering. A single `/proc/cpuinfo` read is deliberately *not* evasive; a dozen reads across categories followed by silence is.

**Evidence.** Two real captures back this. `tests/fixtures/strace-evasive-real.log` (a probe that reconnoiters, then exits) scores 100/100 `evasive`, `recon_then_quiet=True`, `impact=0`, `inconclusive=True`. `tests/fixtures/strace-real.log` (the benign Phase 0 capture, which reads `/etc/passwd` and writes files) scores 0/100 `none`. The distinguishing term is not raw event count — the real evasive capture is 1586 lines — it is *impact*: writes to non-excluded paths and IP connects. That is what separates "looked around and did nothing" from "looked around and then acted".

**Why it matters.** Before this, a sample that detected the sandbox and exited produced a clean-looking, event-thin run. Now the evasion itself is the finding. The score is also the natural trigger for escalating to a stronger tier later.

---

## D13 — gVisor is the intended default where available; a tier-2 host is a stated goal, not a claim

**Decision.** The tier model already ranked gVisor (`runsc`) above shared-kernel and below microVM, and `runsc-hatchery`/`runsc` map to tier 2. This revision makes the tier genuinely usable: `scripts/install-runsc-docker-runtime.sh` installs runsc and registers a Docker runtime with the Sentry trace on, for hosts that want a real boundary without `/dev/kvm`.

**Honest status.** This host (macOS + colima) has no `runsc`, and installing one restarts the Docker daemon used by other workloads, so it was **not** installed here. The single most important open question from the handoff — *does `strace` still function inside a gVisor sandbox?* — is therefore answered at the design level rather than by a live detonation: the per-tier strategy does not rely on ptrace at tier 2 and instead uses gVisor's own trace (D11). Verifying it end-to-end needs a Linux host with `runsc` and Raphael's approval to install it, which is exactly the "ask first" boundary in the handoff.

**Trade-off accepted.** Registering the runtime globally with `--strace` traces every container under it, which costs performance. A dedicated analysis host is the intended deployment; the script says so.

---

## What was deliberately not done

- **Rewriting the MITRE mapping for ATT&CK v19.** It is a real gap: v18 (Oct 2025) replaced detections with **Detection Strategies** and **Analytics** and deprecated Data Sources; v19 (Apr 2026) split Defense Evasion into **Stealth** and **Impair Defenses** and deleted Rootkit and Modify Registry as standalone techniques. Doing this properly means touching every rule's metadata and the mapper, and doing it half-way is worse than flagging it. Scheduled as Phase 2 and marked ⚠️ in the README.
- **AI triage.** Phase 3, deliberately after the pipeline is trustworthy. When it lands it will use versioned prompt contracts, JSON-schema-validated output, grounding requirements and fail-closed suppression, in the shape Microsoft documented for DTDA. Critically, **sample-derived text is untrusted input**: Microsoft's Project Ire write-up notes a sample containing the literal string `BelievemeIamMustang-Panda`, explicitly flagged as *"adversarial input to LLM-driven analysis, biasing the verdict."* Any LLM layer here must treat malware strings as data, never instructions.
- **Making tier 1 safe.** It cannot be. The honest response is to label it, not to pretend.

---

## Primary sources

**Isolation.** Firecracker design docs; gVisor security model, platforms and performance guides; Kata Containers docs; "Firecracker vs Cloud Hypervisor vs Kata Containers" (Jul 2026), including the Dirty Frag container-vs-microVM evaluation; Northflank Kata/Firecracker/gVisor comparison (Jan 2026); Fly.io "Firecracker vs gVisor" (Sep 2026); safeguard.sh container-runtime comparison (Feb 2026).

**Syscall observability.** "strace vs eBPF Tracing (2026)"; "From strace to eBPF" (Jun 2026); Siglabs eBPF runtime-security research roundup (Jun 2026); InfoQ "Kernel-Level Ground Truth" (May 2026); LADC 2025 paper on eBPF versus VMI for high-interaction honeypots; Datadog Security Labs, "Detection primitives for eBPF rootkits" (Jul 2026) for VoidLink, LinkPro and Atomic Arch.

**Detection content.** mandiant/capa releases v9.0–v9.3; VirusTotal "YARA-X is stable!" (Jun 2025) and "VirusTotal moves to YARA-X"; Andrea Fortuna, "Threat hunting with YARA-X" (Apr 2026).

**Frameworks.** MITRE ATT&CK v18 release notes and v18.0→v18.1 detailed changelog; "ATT&CK v18: The Detection Overhaul You've Been Waiting For" (Oct 2025); ATT&CK v19 announcement (Apr 2026); NIST SP 800-61r3 (Apr 2025).

**Commercial and OSS landscape.** CAPEv2 documentation; Joe Sandbox v44 "Smoke Quartz" release notes (Jan 2026); VMRay; Recorded Future Triage; Cyberpress "Malware Analysis Tools 2026".

**AI triage.** Microsoft Research, "Ire identifies another LOTUSLITE specimen" (Jun 2026); VirusTotal, "Reversing at Scale: AI-Powered Malware Detection for Apple's Binaries" (Nov 2025); arXiv, "GenAI-Driven Threat Detection with Microsoft Security Copilot" (DTDA, 2026).

**Evasion.** Zscaler, "New HijackLoader Evasion Tactics"; SonicWall, "HijackLoader Delivered via SVG files" (Oct 2025); Picus, "T1497.003 Time Based Checks" (Apr 2026); anti-analysis technique catalogs (Feb 2026); "Malware Sandbox Evasion" (pwnsy).
