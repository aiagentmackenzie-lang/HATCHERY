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

Python 3.12–3.14 is supported; 3.15 is excluded until a capa dependency ships a
wheel.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

hatchery doctor          # what isolation can this host actually give you?
hatchery build           # build the sandbox image
hatchery submit sample.elf --timeout 120
```

A clean checkout is verified end to end (CLI, compiled API, queue worker and
dashboard proxy) by `scripts/verify_setup.sh`. The captured result and acceptance
fixtures are in [`docs/BASELINE.md`](docs/BASELINE.md); the fixture scorecard
currently records **no known defects** (the ELF parser, the unreadable-PCAP path
and the two mis-calibrated rules were closed by D36/D37).

Output lands in `results/<task_id>/`:

```
results/<task_id>/
├── manifest.json        # D33: SHA-256 of every file below, written last
├── bundle/
│   ├── analysis.json     # the whole analysis document (schema 1.1), incl. limitations
│   │                     #   and static.pe / static.elf for parsed binaries
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

The two files in `bundle/` are the source of truth. The API ingests them; the dashboard renders them; the Markdown report is generated from the same data. `manifest.json` describes the files (never the findings) and is what `hatchery results verify` recomputes — it lives at the run root so every existing reader is untouched.

```bash
hatchery results verify results/<task_id>      # intact / unsealed / broken, with the path
hatchery results seal results/<task_id>        # make a run written before D33 verifiable
```

---

## Capability matrix

Not aspirational. What is in the code today.

| Capability | Status | Notes |
|:--|:--:|:--|
| Hash (MD5/SHA1/SHA256), string extraction, PE/ELF parsing | ✅ | PE structure + imports; ELF header/sections/symbols/dynamic/security (D36); both are carried in the bundle as `static.pe`/`static.elf` (D38), rendered in `report.md` and persisted by the API |
| YARA-X scanning | ✅ | Rust engine; YARA 4 is in maintenance mode upstream |
| Rule lint gate (`hatchery rules lint`) | ✅ | naming + required metadata are CI errors, not warnings |
| capa capability extraction | ✅ | static capa 9.x, plus `capa_dynamic` (below) over emulator memory snapshots |
| Packer detection | ✅ | UPX, VMProtect, Themida, MPRESS, NSIS, generic |
| Detonation under syscall tracing | ✅ | Linux ELF; artifact recovery verified end-to-end |
| **Per-tier monitoring strategy** | ✅ | every bundle names the collector used *and its blind spots*; a downgrade says so |
| **Evasion detection (scored, first-class)** | ✅ | recon breadth + ordering; a recon-then-quiet run is reported evasive/inconclusive |
| **gVisor tier-2 runtime + Sentry collector** | ✅ | per-container OCI annotations enable runsc's Sentry trace; the engine reads it back and emits `source="gvisor-sentry"` events |
| **eBPF syscall collection** | ❌ | intended for tier 3; tier 1 uses `strace` and **tier 2 uses gVisor's Sentry trace** |
| Filesystem monitoring (inotify) | ✅ | |
| Network capture (tcpdump → PCAP) | ✅ | parsed; an unreadable capture is an error, never an empty result (D37); **egress is blocked**, so a capture is usually empty by design |
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
| **Windows PE emulation (config extraction)** | ⚠️ | Mandiant **Speakeasy 2.0.0b6** (MIT, pre-release) in a container at the probed tier; extracts C2 endpoints, user agents, mutexes, registry persistence and dropped files from an emulated run. **Not isolation and not ground truth** — the sample's instructions are interpreted, not executed. See D21 |
| **`capa_dynamic` (capa over memory snapshots)** | ⚠️ | static capa + YARA over the emulator's captured memory regions (unpacked/decrypted code), labelled separately from static capa. A Speakeasy→CAPE adapter is deliberately not built |
| **Windows / macOS native dynamic analysis** | ❌ | no Windows guest; Windows PE is emulated, not executed natively |
| **Delivery-format intake (ZIP/OOXML, tar/gzip/bzip2/xz, HTML/SVG, LNK, ISO9660/IMG, PDF, OLE/CFB, RTF)** | ⚠️ | one bounded intake path; containers are unpacked and their children analysed statically. LNK and ISO9660 are fully parsed; PDF is targeted (embedded files + JavaScript); OLE/CFB compound files are enumerated and their embedded VBA macros **decompressed to source** and `\x01Ole10Native` packages carved out; RTF `\objdata` objects are decoded and an OLE payload is fed straight back to the OLE parser. 7z, RAR and CAB are *detected and reported as unsupported* with a reason — never silently skipped |
| **Unpacking / config extraction** | ⚠️ | Windows PE config comes from emulation (above, D21). Delivery containers are unpacked statically (D19); 7z, RAR and CAB are detected and reported as unsupported |
| **AI triage** | ⚠️ | `hatchery triage <run_dir>` / `submit --triage` runs a **local** Ollama model under a versioned prompt contract: JSON-schema-validated output, every claim must cite an evidence id that exists in the run, and a verdict left with no grounded finding is INCONCLUSIVE. Sample text is wrapped in an untrusted-data boundary (an anti-injection test is in CI). A remote endpoint or a `:cloud` model is refused unless `--allow-remote-model`; the run says so when it is. Advisory only — not ground truth |
| **Candidate Sigma rules** | ⚠️ | generated drafts from observed behaviour; labelled as requiring review, never claimed validated |
| **Campaign clustering** | ⚠️ | `hatchery cluster [path]` fingerprints each run from what the engine already recorded (import hash, imports, capa, YARA, ATT&CK, IOCs, emulated APIs, sections, classified strings — the PE import/export features only became real in D38, when `static.pe` gained a producer) and groups similar runs by a weighted Jaccard score with a token simhash cross-check. Derived on demand — never a second producer. Lists the shared features that justify each group and **never names a family**: similarity is a lead, not attribution. 34 tests |
| **MCP server** | ⚠️ | `hatchery mcp` exposes `submit_sample`, `list_runs`, `get_report`, `get_iocs`, `triage_run` and `cluster_runs` over newline-delimited JSON-RPC 2.0 on **stdio**, so an agent can call HATCHERY as a tool. Stdlib only, no SDK. Local stdio only — never expose it on a socket; the `triage_run` tool cannot be told to use a remote model |
| **Deterministic replay** | ⚠️ | `hatchery replay <run_dir>` re-analyses the same sample under the settings the bundle recorded and classifies every signal. Deterministic static facts (hashes, file type, delivery format + child hashes, YARA rule set, capa capability set, ATT&CK id set, static IOC set) must be identical or the replay is a loud `static-mismatch`; dynamic observations (event counts, durations, IOC order, evasion score) are reported as drift and never failed on. A missing/changed sample, an unreproduced tier/collector, or a bundle missing a section is INCONCLUSIVE, never a silent pass. The old bundle is never mutated — see D26 |
| **Durable job queue + workers** | ⚠️ | `hatchery submit --enqueue` writes a job to a stdlib-SQLite queue and `hatchery worker` executes it by running the existing `submit` pipeline (one producer per data path). Atomic claims (`BEGIN IMMEDIATE`) so two workers never run the same job, bounded `--concurrency`, a lease renewed while a job runs, and **fail-closed recovery**: an expired lease is requeued and, after `max_attempts`, failed with the reason — never left `running`. The bundle is the authority, so exit 0 without a bundle is a failure and `worker --once` exits non-zero if a job failed. The API enqueues instead of spawning and reflects queue state on read. Single host only — no broker or remote workers; see D27 |
| **Sample store: content-addressed, encrypted at rest, retention** | ⚠️ | One store (`engine/store/`) for direct submit, `--enqueue`, the worker, replay and `hatchery store`. Samples are addressed by sha256, stored as AES-256-GCM envelopes (versioned, authenticated header, key id) with a SQLite index, 0600 blobs and atomic writes; no write path emits plaintext. `prune` is a dry run unless `--apply`, its TTL is explicit and disabled by default, and it never deletes a sample referenced by a run bundle or a queued/running job — if a reference cannot be resolved it refuses. `cryptography` is now a declared runtime dependency (D28) |
| **Key ring, rotation and recoverable backups** | ⚠️ | A versioned `0600` key ring holds the active key plus retired keys; decryption resolves the envelope's key id **by id** (no trial decryption), and a missing key is `unknown-key-id` naming the key id and blob. `hatchery store key rotate` re-wraps every non-active blob with the same atomic write path, is resumable through `rotation.in_progress`, takes the store lock (a second rotation reports `store-locked`), and is complete only when no blob needs a retired key; `key retire` is refused while a blob still needs it. `store backup` copies blobs+index+queue using SQLite's backup API, hashes every blob, excludes the key by default and writes the manifest last; `store restore` validates the backup as hostile input, authenticates every blob in memory and preserves index rows and job ids/states/attempts. D28's env/file/generated single-key store keeps working unchanged (D29) |
| **Result-bundle integrity, retention and growth** | ⚠️ | `results/<run>/manifest.json` is a deterministic SHA-256 manifest written **last** by the one writer every mutating stage calls (`submit`, `triage`, `push`, `replay`), at the run root so `bundle/` — and every reader of it — is unchanged. A run directory's conclusion **includes its nested units** (D34): `hatchery results verify` recomputes every hash and names the first break (`modified`, `missing`, `extra`, `truncated`, `symlink`, `manifest-invalid`, `manifest-version`, `manifest-missing`, `replaced`, `nested-unsealed`, or the distinct state `unsealed` — never `ok`); a nested replay with no manifest is `nested-unsealed`, `ok: false`, exit 1. `--expect-manifest` is the operator's anchor and is what catches an artifact rewritten together with its manifest; it proves the parent manifest, not the nested units. `hatchery results seal <run>` makes a legacy run verifiable (idempotent, refuses a mismatch, `--replace` prints the old hash); `seal <root> --all` brings a corpus into that state depth-first and idempotently, refuses tamper and refuses `--replace` in batch. `scripts/verify_manifest.py` is the recipient's verifier: stdlib only, the same `verify_run`, same classifications and exit codes. Retention is **off by default**, applied only by `hatchery results prune --apply` (dry run otherwise), refuses the whole plan for a run it cannot verify (including `nested-unsealed`), always keeps the newest `--keep-last` (minimum 1, clamped and reported), renames before it removes (crash-resumable), serialises on a `flock` and appends a `0600` prune record. `hatchery results status` reports runs/bytes/oldest/newest/unsealed counts/strays/what a prune would remove and warns at `HATCHERY_RESULTS_WARN_RUNS`/`_BYTES` without ever deleting. A contended sample store is `store-busy` (exit 1), never a traceback. The manifest is **not signed and not MAC'd**, and `results/` is **not encrypted**: an artifact *and* manifest rewritten together are caught only by the anchor. See D33/D34 |
| **API credentials, CORS and a keyed audit log** | ⚠️ | Tokens are rows, not environment variables: an id, a role (`admin`/`viewer`), a non-secret prefix, created/expiry times and a revoked state, stored as `sha256(domain \|\| token)`. `npm run token -- create\|list\|retire\|expire` generates the secret locally and prints it **once**; there is no create endpoint and no raw token in the database, a log, an error, a response or the audit log. Retirement and expiry are checked per request, so rotation needs no restart, and bootstrap `HATCHERY_ADMIN_TOKEN`/`HATCHERY_READ_TOKEN` (plus the back-compatible `HATCHERY_API_TOKEN`) always win as the recovery path. CORS is an exact allow-list (the dashboard origin on 5173 plus `HATCHERY_ALLOWED_ORIGINS`), never a reflection. Every audit row carries `prev_hash`/`entry_hash` (SHA-256) **and** `entry_mac` (HMAC-SHA-256 from a local rotatable key ring), appended under `BEGIN IMMEDIATE`; recomputing the digests is not enough to forge the log. `GET /api/audit/verify` names the first `forged`, `modified`, `deleted`, `inserted`, `unkeyed`, `unknown-key`, `truncated` or `replaced` row and reports its own `assurance` (`empty`/`unkeyed`/`mixed`/`keyed`) and `coverage`. A truncation that also rewrites the stored head is only caught against a head recorded elsewhere (`npm run audit -- head` → `verify --expect-head`), and the API database is `0600` — see D30/D31. **The log is finite (D32)**: a documented retention policy, off by default and applied only by `npm run audit -- compact --apply`, archives the oldest segment to a `0600` JSONL file plus a last-written manifest and hands the chain off (`prev_hash` = the archived tail); verification reads the archives, reports the segments, the manifest hash and a proven join, and treats a missing/tampered/non-linking archive as a break; archives verify offline; growth is warned about in `audit status`, the verify response and the startup banner and never auto-deleted |
| **MISP / OpenCTI push** | ⚠️ | `hatchery push` transports the run's single STIX 2.1 bundle to MISP (`/events/upload_stix/2`) or OpenCTI (TAXII 2.1 push); fail-closed, token never persisted. Wire format pinned; live-instance compatibility untested |

---

## Known limitations (structural, not bugs)

1. **The Linux-only guest cannot hide its host.** KVM/CPU count/RAM/uptime are readable through `/proc` at any tier. No amount of environment faking fixes this; only a VM with a real guest kernel helps, and even then CPUID reports the hypervisor.
2. **Containers share a kernel.** At tier 1 there is no boundary. Run malware you do not trust only at tier 2 or 3, on a machine you are willing to lose.
3. **Egress is blocked by default.** The sandbox network is `internal`, so a sample cannot reach its real C2 or exfiltrate. The cost is that samples requiring a live internet will not fully detonate. A believable simulated internet is future work.
4. **Windows malware is analyzed statically.** Dynamic Windows analysis needs a Windows guest, which needs licensing and hardware virtualisation.
5. **`strace` is the tier-1 fallback, not the ambition.** ptrace-based tracing has high overhead and is detectable; in 2026 eBPF rootkits exist that `SIGKILL` processes which attempt to `ptrace` a protected PID. Tier 2 no longer uses ptrace: it reads gVisor's own Sentry trace from the runsc debug log. eBPF-based collection for tier 3 is the intended direction — see [`docs/DECISIONS.md`](docs/DECISIONS.md) D2, D11, D14.
6. **What each collector cannot see.** At tier 1, `strace` cannot see time-based checks: `RDTSC`, `CPUID` and vDSO-served `clock_gettime` are CPU/userspace operations, not syscalls (the probe in `tests/fixtures/strace-evasive-real.log` ran a `date +%s` loop and produced no clock syscall). At tier 2, gVisor's Sentry trace *does* capture `clock_gettime` — the vDSO path becomes a Sentry syscall — but `RDTSC`/`CPUID` remain instructions and are not emitted. Every run names its collector and that collector's blind spots, and reads `summary.evasion_*` from whatever source it actually had.
7. **Tier 2 was verified end-to-end on this host.** gVisor needs no KVM and the registration script exists; installing `runsc` and wiring its Sentry trace were verified against a real detonation. Two consequences are documented rather than hidden: gVisor's trace is container-wide, so the engine attributes events to the sample's process subtree and records how many entrypoint/monitor events it excluded; and Docker's `get_archive` cannot see files written inside a gVisor container because the rootfs overlay is in-memory, so the in-guest strace/inotify/dropped artifacts are recovered copy-based through a named Docker volume read back by a short `runc` sidecar — no host bind mount (D5). The Sentry trace remains the syscall collector.
8. **Delivery-format coverage is partial, and says which part.** A ZIP/OOXML package, a tar/gzip/bzip2/xz archive, an HTML/SVG page, a Windows shell link (LNK), an ISO9660/IMG image, a PDF, a legacy Office OLE/CFB compound file, or an RTF document with an embedded object is unpacked on one bounded path and each extracted child is hashed, classified and run through YARA/strings/packer detection. LNK target/arguments/working-directory/icon fields and ISO9660 (incl. Joliet) directory trees are fully parsed; PDF is targeted at embedded files and JavaScript rather than a full object-graph parse; OLE/CFB streams are enumerated, embedded VBA projects are decompressed with MS-OVBA so the extractor sees the macro *source* rather than opaque compressed bytes, and `\x01Ole10Native` package streams are carved to recover the embedded file; an RTF `\objdata` object is decoded (hex or `\bin`) and, when it is an OLE compound file, recursed into the same OLE parser so its VBA and package payload are recovered too. Extracted children are **not detonated**, and the run states that. Formats that are detected but not extracted in this revision — 7z, RAR, CAB — are listed as unsupported with a reason, so a document is never an empty result. Extraction is bounded (depth, child count, per-entry and total size, compression ratio, symlink/device refusal, path-traversal confinement); hitting a bound is recorded, not hidden.

9. **Emulation is a separate, fail-closed stage — not a boundary and not ground truth.** Windows PE config extraction and `capa_dynamic` run Mandiant Speakeasy 2.0.0b6 (a **pre-release**, MIT) inside a container at the probed tier, with `--network none`, a read-only sample, all capabilities dropped, a non-root user and memory/CPU/PID/wall-clock caps. The sample's x86/x64 instructions are interpreted by a software CPU and its Windows APIs emulated in Python — **it never executes natively**, and emulation does **not** raise or lower the isolation tier (the bundle records both). It is gated on having a boundary: with no container runtime it is unavailable and declared, and the off-by-default `--allow-host-emulation` escape hatch runs it on the bare host and is loudly labelled as unsupported. Where it runs it is fail-closed: APIs the emulator does not implement, emulator detection, and the absent real network are declared blind spots, and a crash, a wall-clock cap, or an empty report is **INCONCLUSIVE**, never clean. `capa_dynamic` is static capa/YARA over the emulator's captured memory snapshots — **not** a Speakeasy→CAPE conversion, which is deliberately not built. Emulation events live in a separate `emulation-events.jsonl` stream, not in the native `events.jsonl`. See D21.

10. **Encryption at rest has a local key and a local store.** The key is an environment variable, a local file, or the store's own `0600` key ring — there is no KMS/HSM and no escrow. Rotation is built (D29): `hatchery store key rotate` re-wraps every blob onto a new active key, resumably and atomically per blob, and `key retire` removes the old key only when no blob needs it. The auto-generated key (and the ring, when it exists) sits beside the ciphertext, which protects against plaintext at rest (backups, snapshots, a copied directory) but not against an attacker who can read the store directory. Backups are built (D29): `hatchery store backup` uses SQLite's backup API for the index and queue, hashes every blob, writes the manifest last and excludes the key by default; `store restore` refuses a non-empty target, a newer schema, a path-traversal manifest and a tampered blob, and reports any entry it cannot decrypt rather than claiming success. Rotation and backups are single-host: a results tree on another machine is not consulted, so an operator pruning on two hosts must point each at the other's bundles or accept that the other host's references are invisible. Replay's single-use staging file is a plaintext file in the OS temp directory for the duration of the submit subprocess; SIGKILL can leave it there. See D28, D29, [`docs/RETENTION.md`](docs/RETENTION.md) and [`docs/BACKUP.md`](docs/BACKUP.md).

11. **The audit log is finite by policy, not by a timer.** `audit_log` never shrinks on its own: the serving process has no pruning path, no scheduled task and no background timer. A documented retention policy (`--older-than`, `--max-rows`, always keeping a live anchor row) is applied only by `npm run audit -- compact --apply`, which archives the oldest segment to a `0600` JSONL file plus a last-written manifest and then deletes exactly that window in one transaction. Nothing is re-hashed: the live rows keep their digests and MACs and the archived rows keep theirs, so the handoff — the live chain's first `prev_hash` equalling the archived tail — is what makes the join provable. Verification reads the archives and reports the segments, the manifest hash and the join; a missing, tampered or non-linking archive is a break with its own classification, and `assurance` still describes the live rows only, so read `assurance` and `archive_verified` together. An archive can be verified offline (chain + MACs + manifest hash + tail) on a machine that never held the database, as long as the key ring travels with it. Growth is warned about (`HATCHERY_AUDIT_WARN_ROWS`, `HATCHERY_AUDIT_WARN_BYTES`) in `audit status`, in every verify response and in the startup banner, and **never** auto-deleted. What is not protected: archives are owner-readable and unencrypted, their manifests are unsigned (an attacker who can rewrite an archive *and* its manifest consistently can present a different internally consistent one — the tail hash in `audit_chain_meta` is what catches that against a live database you still trust), pre-D30 rows are never archived, there is no scheduled compaction, no off-host shipping and no multi-host story, and a root attacker is out of scope. See D32 and [`docs/AUDIT-RETENTION.md`](docs/AUDIT-RETENTION.md).

12. **A result bundle is verifiable and finite, not confidential or signed.** `results/<run>/manifest.json` records SHA-256 per file and is written last by every stage that touches the run, so `hatchery results verify` can prove the directory — including every nested replay unit, since D34 — has not changed since that stage, and `hatchery results prune --apply` can make the corpus finite without deleting a run it cannot verify. Three limits are stated rather than implied away: the manifest is **unsigned and unMAC'd** (an attacker who rewrites an artifact *and* regenerates the manifest is caught only by a `--expect-manifest` anchor you recorded elsewhere — the same anchor rule as D31/D32), `results/` is **plaintext** (it holds attacker-controlled artifacts; every reader is path-based), and retention is **off by default and operator-applied** (no timer, no background task; a run with no manifest, or a nested unit with none, blocks the whole apply). A run copied without its manifest verifies as `unsealed`, which is the honest answer. `hatchery results seal <root> --all` brings an existing corpus into the verifiable state; `scripts/verify_manifest.py` lets the recipient check the claim with Python and nothing else. See D33/D34 and [`docs/RESULTS.md`](docs/RESULTS.md).

---

## CLI

```
hatchery doctor                     Host readiness: isolation tiers, image, rules, emulation
hatchery build [--emulation]        Build the sandbox image (and the emulator image)
hatchery submit <file>              Static + dynamic analysis
hatchery submit <file> --enqueue    Queue the job for a worker instead of analysing now
hatchery worker [--once]            Run a queue worker (claim, execute, recover)
hatchery queue [job_id]             Show the job queue, or one job
hatchery store status|verify|migrate|prune|keygen   Sample store: encryption, integrity, retention
hatchery store key status|rotate|retire            Key ring, rotation and retirement (D29)
hatchery store backup|restore                      Recoverable store + queue backups (D29)
npm run audit -- status|compact|archives          Audit-log retention: report growth, archive a segment (D32)
npm run audit -- verify [--archive FILE]          Verify the chain, its archives, or an archive offline (D32)
hatchery results verify <run>                     Recompute the bundle manifest; name the first break (D33/D34)
hatchery results seal <run>                       Seal a run written before D33 (idempotent)
hatchery results seal <root> --all                Seal every run under a results root, nested units first (D34)
hatchery results status                           Runs, bytes, oldest/newest, unsealed counts, strays, growth (D33/D34)
hatchery results prune [--older-than 30d] [--keep-last N] [--apply]   Bundle retention (D33/D34)
python scripts/verify_manifest.py <run>           The recipient's verifier: Python 3 and nothing else (D34)
hatchery emulate <file>             Windows PE emulation (static + emulator, no detonation)
hatchery static <file>              Static analysis only
hatchery status <task_id>           Task status
hatchery report <task_id>           Print a completed report
hatchery iocs <task_id>             IOC summary
hatchery rules lint                 Lint the YARA rules (exits 1 on error)
hatchery push <run_dir> --target misp|opencti   Push the run's STIX bundle
hatchery triage <run|bundle>        Local LLM triage over an existing run (advisory; accepts the run dir or its bundle/)
hatchery cluster [path]             Group analysed runs that look like the same campaign
hatchery mcp                        Run the MCP server on stdio (for an agent to call)
hatchery replay <run_dir>           Re-analyse a run and report whether its static findings reproduce
```

Options for `submit`: `--timeout SECONDS`, `--output/-o DIR`, `--no-sandbox`, `--emulate`, `--emulate-timeout SECONDS`, `--emulate-raw`, `--no-emulate-capa`, `--allow-host-emulation`, `--triage`, `--triage-model NAME`, `--allow-remote-model`, `--enqueue`, `--queue PATH`, `--job-id ID`, `--requeue`.

Options for `worker`: `--once` (drain and exit), `--concurrency N` (default 1), `--queue PATH`, `--lease SECONDS`, `--poll-interval SECONDS`, `--timeout SECONDS`, `--worker-id ID`.

Options for `queue`: `--json`, `--status STATE`, `--limit N`, `--recover` (requeue or fail jobs whose worker lease expired), `--queue PATH`.

Options for `replay`: `--output/-o DIR`, `--no-sandbox`, `--allow-host-emulation`, `--sample PATH`, `--timeout SECONDS`, `--require-manifest`, `--json`.

Options for `results`: `verify RUN [--expect-manifest SHA256] [--json]`; `seal RUN [--replace] [--json]`, or `seal ROOT --all [--json]` (depth-first, idempotent, `--replace` refused in batch); `prune [--older-than 30d] [--keep-last N] [--apply] [--results DIR] [--json]`; `status [--older-than] [--keep-last] [--results DIR] [--json]`. Retention defaults come from `HATCHERY_RESULTS_RETENTION_DAYS` and `HATCHERY_RESULTS_KEEP_LAST`; growth warnings from `HATCHERY_RESULTS_WARN_RUNS` (2000) and `HATCHERY_RESULTS_WARN_BYTES` (10 GiB), `0` disabling either. Exit codes: 0 intact (or unsealed), 1 broken or refused, 2 usage; `seal --all` exits 0 when nothing was refused, 2 when a run was refused and 1 on an operational error. JSON goes to stdout, diagnostics to stderr.

Options for `store`: `--store DIR` (else `HATCHERY_SAMPLE_STORE`), `--results DIR`, `--queue PATH`, `--json`. `status` and `prune` take `--ttl SECONDS` (0 disables; else `HATCHERY_SAMPLE_TTL`); `prune` deletes only with `--apply`; `verify` takes `--sha`; `migrate` takes `--dry-run` and `--adopt-queue/--no-adopt-queue`; `keygen -o PATH` writes a 0600 key file. `store key rotate` takes `--dry-run` and `--key-file PATH`; `store key retire KEY_ID` is refused while a blob needs the key; `store backup -o DIR` takes `--include-key` (explicit, loudly warned, writes the ring 0600) and `--queue PATH`; `store restore BACKUP --target DIR` takes `--force` (a differing blob is still never overwritten) and optional `--queue`/`--store` targets. Exit codes: 0 success, 1 operational error or a refusal that wrote nothing, 2 verification/state failure (including a refused prune, an incomplete rotation, a backup of a plaintext store, or a restore with undecryptable entries). JSON goes to stdout, diagnostics to stderr, and no command prints a key.

### Emulation (Windows PE)

`hatchery emulate sample.exe` (or `hatchery submit sample.exe --emulate`) runs Mandiant **Speakeasy 2.0.0b6** inside a container at the probed isolation tier and extracts runtime configuration a statically packed sample never reveals: C2 endpoints, user agents, mutexes, registry persistence and dropped files. It also runs `capa_dynamic` — static capa and YARA over the emulator's captured memory snapshots. The extra is opt-in (`pip install -e ".[emulation]"`) and the image is built with `hatchery build --emulation`. Emulation is **not isolation and not ground truth**: the sample is interpreted, not executed, and a crash, timeout, unimplemented API or empty report is INCONCLUSIVE. See [`docs/DECISIONS.md`](docs/DECISIONS.md) D21.

### Push to MISP / OpenCTI

`hatchery push results/<task_id> --target misp` sends the **existing** `stix_bundle.json` to MISP's STIX 2.1 import endpoint; `--target opencti` sends the same objects as a TAXII 2.1 envelope to a TAXII Push collection. Configure either with flags (`--url`, `--token`, `--collection`) or the environment:

```bash
export HATCHERY_MISP_URL=https://misp.example   HATCHERY_MISP_API_KEY=...
export HATCHERY_OPENCTI_URL=https://opencti.example   HATCHERY_OPENCTI_TOKEN=...   HATCHERY_OPENCTI_COLLECTION=<taxii-collection-id>
```

A non-2xx response or a transport error exits non-zero with the reason; the outcome is written to `push-<target>.json` next to the run, **without** the token. TLS verification is on by default (`--insecure` warns). See [`docs/DECISIONS.md`](docs/DECISIONS.md) D20 — the wire format is tested against a local server; live-instance compatibility is untested here.

### AI triage (local model)

`hatchery triage results/<task_id>` (or `hatchery submit sample.bin --triage`) asks a **local** Ollama model for a grounded triage of the run. It is the last ❌ in the capability table turned into a working, honest ⚠️. The point is the contract, not the model:

- **Local by default.** The default endpoint is `http://127.0.0.1:11434`; a non-loopback endpoint is refused unless `--allow-remote-model`. A `:cloud` Ollama model is also refused by default — it is reached through localhost but runs on someone else's GPU, so the loopback check alone does not keep the sample at home. Both are reported in the run.
- **A versioned prompt contract.** The system prompt, JSON schema and version are hashed into every result, so a contract change is visible per run rather than silent. Ollama's structured-output `format` constrains decoding; HATCHERY then re-validates the object itself, because the runtime is not the validator.
- **Grounding or nothing.** Every finding must cite an evidence id that exists in the run (`event:12`, `rule:...`, `ioc:...`, `capa:...`, `technique:...`, `emulation:api:...`, `delivery:child:...`). Citations are normalised from the loose form a small model emits, and any finding that does not resolve is dropped. A verdict left with no grounded finding, an unparseable response, a timeout, or no model at all is **INCONCLUSIVE**, never clean.
- **Malware strings are hostile input.** Sample-derived text is delivered inside an `<untrusted-sample-data>` boundary that the sample cannot close, and the prompt forbids following instructions found inside it. A model that obeys an injected instruction still cannot produce an ungrounded verdict. An adversarial-string test runs in CI.
- **Techniques are validated, not trusted.** A model-proposed ATT&CK id is accepted only if it exists in the pinned dataset (D15); it is labelled *model-suggested* because validating an id is not proving the association.

The default model is auto-selected from the local models that can generate text (a small-model preference order, then any local completion model). Set `HATCHERY_TRIAGE_MODEL` or `--triage-model` to pin one. On a weak machine the model may cold-load, so `--timeout` is generous by default and the model is kept warm between calls. See [`docs/DECISIONS.md`](docs/DECISIONS.md) D22.

### MCP server

`hatchery mcp` runs HATCHERY as an [MCP](https://modelcontextprotocol.io) server on **stdio**, so an agent can call the engine as a tool. It speaks newline-delimited JSON-RPC 2.0 (stdlib only, no SDK) and exposes six tools:

| Tool | What it does |
|---|---|
| `submit_sample` | Analyse a local sample (static-only by default; `no_sandbox=false` detonates, `triage=true` adds local triage) |
| `list_runs` | List analysed runs under a results root, with hash, event count and triage verdict |
| `get_report` | Return a run's analysis bundle (`json`), Markdown report, `triage` section or `stix` bundle |
| `get_iocs` | A run's indicators, grouped by type |
| `triage_run` | Local LLM triage over an existing run |
| `cluster_runs` | Group runs that look like the same campaign |

Wire it into an MCP client as a stdio server, e.g.:

```json
{
  "mcpServers": {
    "hatchery": {
      "command": "hatchery",
      "args": ["mcp"],
      "cwd": "/path/to/HATCHERY"
    }
  }
}
```

stdout is the protocol channel, so the command prints nothing else. **Local stdio only — never expose it on a socket.** The `triage_run` tool uses a local Ollama model and cannot be told to use a remote one: permitting a remote model stays an explicit operator decision at the CLI, never something an agent can switch on. See [`docs/DECISIONS.md`](docs/DECISIONS.md) D24.

### Reproducibility check (replay)

`hatchery replay results/<task>/bundle` re-analyses the same sample under the settings the bundle recorded and answers the question a finding has to survive: *re-run it and do you get the same static result?*

- **Deterministic must match, or it fails loudly.** sha256/md5/sha1, file type, delivery format and extracted child hashes, the YARA rule-name set, the capa capability set, the ATT&CK technique-id set and the static IOC set are compared for exact equality. Any difference is a `static-mismatch` (exit 2) — the original finding does not reproduce.
- **Dynamic is drift, not failure.** Event counts by category/severity, durations, collected-IOC ordering, evasion score and emulation counters are reported when they move, but a sandbox is not bit-for-bit reproducible and the tool does not pretend it is. Only dynamic movement is a `dynamic-drift` (exit 0).
- **The honest failure is INCONCLUSIVE (exit 1).** The sample is gone or its bytes changed, the replay ran at a weaker isolation tier or without detonation the original had, the emulation image was unavailable, or the bundle predates a stage so a deterministic signal cannot be re-established. A replay never silently passes over a setting it could not reproduce.
- **The sample is located and hash-verified** through the encrypted sample store first (content-addressed, decrypted in memory, plaintext hash checked against the bundle), then the recorded path; `--sample PATH` points at a kept copy. A sample that is purged, expired, encrypted under a different key or tampered is **INCONCLUSIVE** with that reason — never a pass — and replay does not silently fall back to another copy once the store owns the address. A candidate with different bytes is refused rather than replayed.
- **The original bundle is never modified.** The `replay` section and `replay.json` are written beside the **new** run (and a failed replay still writes `replay.json` with the reason). The pipeline is re-run by shelling out to `hatchery submit`, so there is one producer of analysis data.

```bash
hatchery submit sample.elf --timeout 120          # original run
hatchery replay results/<task_id>/bundle          # same static findings? exit 0 = yes
hatchery replay results/<task_id>/bundle --json    # machine-readable replay section
```

See [`docs/DECISIONS.md`](docs/DECISIONS.md) D26 for the signal classes and the verdict precedence.

### Durable queue and workers

`hatchery submit --enqueue` writes the job to a SQLite queue (stdlib, no broker) and returns immediately; `hatchery worker` runs it later. This is what makes an API submission durable: the job's state is a record, not a subprocess the server is holding.

- **The bundle is the authority.** A worker completes a job only when `hatchery submit` exited 0 **and** `bundle/analysis.json` exists. Exit 0 without a bundle is a failure; so is a non-zero exit with a partial bundle. `worker --once` exits non-zero if any job it drained did not complete.
- **Atomic claims and bounded concurrency.** A claim takes the SQLite write lock (`BEGIN IMMEDIATE`), so two workers never run the same job. A worker runs at most `--concurrency` jobs at once (default 1).
- **Leases and recovery.** A running job holds a lease that a monitor thread renews. If a worker dies, the lease expires; the next worker requeues the job, and once it has used its attempts it is **failed with the reason**. It is never left `running` forever and never silently lost.
- **One producer per data path.** The queue is the only writer of job state; the worker executes the existing `submit` pipeline as a subprocess; the server only enqueues and reads.

```bash
hatchery submit sample.elf --no-sandbox --enqueue -o results/my-run   # queue it
hatchery queue                                                         # list jobs and counts
hatchery worker --once --concurrency 2                                 # drain the queue
hatchery worker                                                        # or poll forever
```

Paths are resolved to absolute at enqueue time. The queue database is `data/queue.db` (override with `--queue` or `HATCHERY_QUEUE_DB`). See [`docs/DECISIONS.md`](docs/DECISIONS.md) D27 for the state model, the recovery rules and the deliberate exclusions (no broker, no remote workers, no cancellation).

### The sample store: encryption at rest and retention

Every entry point — `submit`, `submit --enqueue`, the worker, `replay` and `hatchery store` — uses one store, `engine/store/`, at `HATCHERY_SAMPLE_STORE` or `<checkout>/samples`. The root is resolved absolutely, so a CLI run, an API enqueue and a worker agree regardless of the directory each was started from.

- **Content-addressed.** The blob is named by the plaintext SHA-256 and the plaintext hash is re-checked on every read.
- **Encrypted at rest.** AES-256-GCM in a versioned envelope with an authenticated header and a key id. A wrong key, tampered ciphertext, truncated file and unknown version each fail closed with their own reason. Writes are temp-file + `fsync` + atomic rename; the temporary holds ciphertext, and no write path leaves plaintext on disk.
- **Key handling.** `HATCHERY_SAMPLE_KEY` (32 bytes hex/base64) or `HATCHERY_SAMPLE_KEY_FILE` (must be a regular non-symlink file, mode 0600). With neither configured, the first write **generates** a local key at `<store>/.sample-key` (0600) and says so loudly — there is no silent plaintext fallback. Publication is atomic (D35): the material is written to a complete `0600` temporary and linked into place, so a concurrent first writer sees no key or a complete key, never an empty one; a reader that finds an empty file waits 2 s for an older writer and then refuses with `key-invalid` rather than inventing a key. The key is never written to the index, a bundle, a report, a log, argv or an error message; only the key id is printed.
- **Key ring and rotation.** An explicit rotation creates `<store>/.sample-keyring` (versioned, bounded, 0600) holding the active key and retired keys; from then on the ring is authoritative and decryption resolves each blob's key id through it. `store key rotate` re-wraps every non-active blob atomically and resumably (a crash resumes the same key); `store status`/`verify` report per-key blob counts and `rotation_complete`; `store key retire` removes a retired key only when no blob needs it. A D28 env/file/generated single-key store still works with no ring and no migration.
- **Backup and restore.** `store backup` copies the store (blobs + index) and the queue with SQLite's backup API, hashes every blob and writes the manifest last; the key is excluded by default, and `--include-key` is explicit, loudly warned and `0600`. `store restore` validates the manifest/paths/sizes/hashes, authenticates every blob against its content address before writing, refuses a non-empty target, a newer schema and a tampered blob, preserves job ids/states/references, and exits 2 if anything is undecryptable.
- **Retention.** TTL is explicit (`--ttl` / `HATCHERY_SAMPLE_TTL`, seconds) and disabled by default. `hatchery store prune` is a dry run unless `--apply` and prints why every sample was kept or deleted. It never deletes a sample referenced by a run bundle (`sample.sha256` under a results root) or by a queued/running job; a pre-D28 job is protected by hashing the path it still points at, and a job whose sample cannot be identified makes prune refuse.
- **Migration.** `hatchery store migrate` encrypts a legacy plaintext store idempotently and resumes after interruption; `hatchery store verify` decrypts and hash-checks every entry (a legacy plaintext entry is a failure with reason `plaintext-legacy` until migrated). The D27 queue gains a `sample_store_ref` column through a versioned additive migration that preserves job ids and states.

```bash
hatchery store status                       # counts, bytes, encryption, references, reclaimable
hatchery store verify --json                # decrypt + hash-check; exit 2 on any failure
hatchery store migrate                      # encrypt a pre-D28 plaintext store (idempotent)
hatchery store prune --ttl 2592000          # dry run: what would be deleted, and why it was kept
hatchery store prune --ttl 2592000 --apply  # delete expired, unreferenced samples
hatchery store keygen -o ~/.hatchery/sample.key   # 0600, printed key id only
hatchery store key rotate --json            # re-wrap onto a new active key (resumable)
hatchery store key status --json            # per-key blob counts, rotation_complete
hatchery store key retire <old-key-id>      # refused while a blob still needs it
hatchery store backup -o backups/2026-11-21 # SQLite backup API, manifest last, key excluded
hatchery store restore backups/2026-11-21 --target /srv/hatchery-restore   # verifies every entry
```

A worker executes a queued job from the store (`submit --from-store <sha>`), not from the path that was submitted, so deleting the original after `--enqueue` no longer breaks the job. Replay reads and decrypts the stored sample in memory and treats a purged, expired or undecryptable sample as **INCONCLUSIVE** with the precise reason — never as a pass. It still passes the path-based pipeline a single-use staging file (0600, removed when the run ends); that is the one place a plaintext sample exists on disk during replay, and it is documented in [`docs/RETENTION.md`](docs/RETENTION.md).

`HATCHERY_SAMPLE_STORE`, `HATCHERY_SAMPLE_KEY`, `HATCHERY_SAMPLE_KEY_FILE` and `HATCHERY_SAMPLE_TTL` are the store's configuration; `HATCHERY_RESULTS_ROOT` is where reference scans look for run bundles. The key ring lives at `<store>/.sample-keyring` and needs no environment variable. See [`docs/DECISIONS.md`](docs/DECISIONS.md) D28/D29 and [`docs/BACKUP.md`](docs/BACKUP.md).

### Result bundles: integrity, retention and growth

`results/<run>/` is the artifact an analyst hands to a client. It now describes itself: `manifest.json` at the run root records the SHA-256 of every file and is written **last**, by the one writer that every stage mutating a run ends with — `submit`, `triage`, `push`, `replay`. It is a **hash manifest, not a signature**, and it lives at the run root so `bundle/` — and every reader of it (API ingest, replay, clustering, MCP) — is untouched.

- **The honest claim.** The manifest proves the run directory has not changed since the last HATCHERY stage that touched it. It does not claim "unmodified since delivery": after delivery, only an anchor does. Since D34 the claim also covers a **nested unit**: a run whose own files match but which contains a `replay-xxxx/` with no manifest reports `nested-unsealed`, `ok: false` and exit 1 — the directory ships evidence HATCHERY cannot verify.
- **The anchor.** `hatchery results seal <run>` prints the manifest hash; record it when you deliver the run and check it with `hatchery results verify <run> --expect-manifest <sha256>`. That catches an artifact rewritten **together with** its manifest, and a deleted manifest is unambiguous. Without an anchor, an attacker who rewrites both is not detected — stated, not implied away. A matching anchor can sit alongside `ok: false`: it proves the parent manifest you recorded, not that every nested unit in the directory is verifiable, and the human output says so explicitly.
- **Verification names the break.** `modified`, `missing`, `extra`, `truncated`, `symlink`, `manifest-invalid`, `manifest-version`, `manifest-missing`, `replaced`, `nested-unsealed`, and the distinct state `unsealed` (a legacy run, never `ok`). A symlink is never hashed through, and a manifest path that escapes the run is `manifest-invalid` rather than followed. A nested **broken** unit keeps its own classification and a prefixed path (`replay-xxxx/bundle/analysis.json`).
- **Sealing a legacy corpus.** `hatchery results seal <run>` is idempotent (a valid manifest is returned unchanged), refuses a manifest that does not match the tree, and `--replace` prints the old hash and says any anchor to it is void. `hatchery results seal <results-root> --all` seals every run under a root **depth-first** (a nested replay before its parent), is idempotent and resumable, reports `sealed`/`already`/`refused`/`ignored`, and exits 0/2/1. It refuses `--replace` in batch: re-sealing mismatches across a corpus would bless tamper wherever it is found. Sealing a nested unit never changes its parent's manifest bytes, so a parent anchor recorded at delivery stays valid.
- **The recipient can check it.** Send `scripts/verify_manifest.py` with the run: `python verify_manifest.py <run> [--expect-manifest SHA] [--json]`. It is **Python 3 and nothing else** — standard library plus the same `verify_run`, no click/rich/YARA-X/capa/Docker, no database and no `HATCHERY_*` environment. It emits the same JSON keys, classifications and exit codes as `hatchery results verify`, because there is exactly one implementation of the rules.
- **Retention is off by default and operator-applied.** `hatchery results prune` is a dry run unless `--apply`; nothing in submit, the worker or the API deletes a run and there is no timer. A run with no manifest, an invalid one, an unparseable bundle **or an unsealed nested unit** is **never** deleted — `--apply` refuses the whole plan and exits 2 (`nested-unsealed` is its own reason in the decisions and the prune log). The newest `--keep-last` runs (default 1, minimum 1, `clamped: true` when it bites) are always kept. Deletion renames to `<run>.deleting-<ts>` first, so a crash leaves a stray the next prune completes and a reader never sees a half-deleted tree.
- **Growth is visible and never enforced.** `hatchery results status` reports runs, bytes, oldest/newest, nested replays, `unsealed_runs`, `unsealed_nested`, strays and what a prune would remove — and says when a prune would be blocked. It warns at `HATCHERY_RESULTS_WARN_RUNS` / `HATCHERY_RESULTS_WARN_BYTES` and never deletes.
- **The sample store composes.** Pruning a run releases a sample only when no other run or queued/running job references it; `store prune` is unchanged and its reference scan is the authority. Concurrent openers of the store now retry the WAL pragma within the existing 60 s timeout and fail as `store-busy` (exit 1, no traceback) rather than leaking `database is locked`.

```bash
hatchery results verify results/<run>                        # intact / unsealed / broken + path
hatchery results verify results/<run> --expect-manifest SHA   # the anchor you recorded at delivery
hatchery results seal results/<run>                          # legacy run -> verifiable (idempotent)
hatchery results seal results --all                          # whole corpus, nested units first (D34)
hatchery results status                                      # count, bytes, unsealed counts, strays, growth
hatchery results prune --older-than 30d --keep-last 5        # dry run: exactly what would go
hatchery results prune --older-than 30d --keep-last 5 --apply
python scripts/verify_manifest.py /tmp/delivery/<run> --expect-manifest SHA
```

Retention defaults: `HATCHERY_RESULTS_RETENTION_DAYS`, `HATCHERY_RESULTS_KEEP_LAST`; growth: `HATCHERY_RESULTS_WARN_RUNS` (2000), `HATCHERY_RESULTS_WARN_BYTES` (10 GiB) — `0` disables either. Replay checks the source manifest first: a mismatch is INCONCLUSIVE naming the file, an unsealed legacy run still replays (recorded as `bundle_manifest: unsealed`), and `--require-manifest` turns that into INCONCLUSIVE. See [`docs/DECISIONS.md`](docs/DECISIONS.md) D33/D34 and [`docs/RESULTS.md`](docs/RESULTS.md).

---

## API

```bash
cd server && npm install && npm run build && npm start   # http://127.0.0.1:3002
cd dashboard && npm install && npm run dev                # http://localhost:5173
```

| Method | Endpoint | Description |
|:--|:--|:--|
| POST | `/api/submit` | Submit a sample (JSON `filePath`, or multipart upload). **Enqueues** the job and returns `status: "queued"` |
| POST | `/api/submit/:id/retry` | Re-analyze an existing task |
| GET | `/api/tasks` | List tasks |
| GET | `/api/tasks/:id` | Task + static + sandbox results + IOC/event summaries |
| GET | `/api/tasks/:id/events` | Behavioral events (paginated, filterable) |
| GET | `/api/tasks/:id/network` | Network connections |
| GET | `/api/tasks/:id/filesystem` | Filesystem events |
| GET | `/api/tasks/:id/report` | Full report (json/markdown) |
| GET | `/api/tasks/:id/iocs` | IOCs (json/stix/text) |
| GET | `/api/audit` | Access audit log (**admin only**) |
| GET | `/api/audit/verify` | Recompute the audit hash chain, bounded (`limit`, `after`); **admin only** |
| GET | `/api/tokens` | List API tokens — id, role, prefix, timestamps, state; **admin only**, never a secret |
| POST | `/api/tokens/:id/retire` | Revoke a token; effective on the next request; **admin only** |
| POST | `/api/tokens/:id/expire` | Move a token's expiry (`at` ISO-8601 or `in_seconds`); **admin only** |
| WS | `/ws` | Real-time event stream |

**Auth and roles.** The API resolves an **actor and role** per request (D25/D30): reads need the `viewer` role, anything that changes state needs `admin`, and `/api/audit`, `/api/audit/verify` and `/api/tokens` are `admin` even though they are GETs. Tokens are compared in constant time; a refusal is a generic `401` (the audit row carries the precise reason).

**Token lifecycle (D30).** Two kinds of credential, with a fixed precedence:

| Credential | Where it lives | Can it expire or be revoked? |
|:--|:--|:--|
| Bootstrap `HATCHERY_ADMIN_TOKEN` / `HATCHERY_READ_TOKEN` / `HATCHERY_API_TOKEN` (admin) | environment | no — it is the recovery path, and it is checked **first** |
| Stored tokens (`htk_<id>_<secret>`) | `api_tokens` in the API's SQLite database, hash only | yes — per request, no restart |

```bash
cd server
npm run token -- create --role viewer --name "ci" --expires-in 30d   # prints the secret ONCE
npm run token -- list                                               # id, role, prefix, state — no secret
npm run token -- retire htk_1a2b3c4d5e6f7a80 --reason "rotated"
npm run token -- expire htk_1a2b3c4d5e6f7a80 --in 0                 # expire now
```

Rotation is create → hand over → retire: adding a token never invalidates another, and retiring one takes effect on the next request. An in-flight request authenticated under the old token finishes. A token's id or prefix is **not** a credential. There is deliberately no create endpoint — a secret must not be minted over the wire — so `POST /api/tokens` is a 404 even for an admin; listing, retirement and expiry are admin-only HTTP endpoints.

**Open mode.** With no bootstrap token *and* no stored token row, the API is unauthenticated and says so loudly at startup twice, with the actor recorded as unauthenticated `anonymous` — it is never described as authenticated. Creating a stored token closes it immediately; retiring the last token does **not** re-open it (recover with the bootstrap pair or the CLI on the host). While it is open, every request is an unauthenticated admin — including the token endpoints — and the audit rows say `authenticated: 0`. That is exactly the risk the startup warning names, and why open mode is a local-development posture, not a deployment.

**Audit log.** Every request the API answers is recorded in the `audit_log` table — actor, role, whether they authenticated, method, path (query string dropped) and status — and readable at `GET /api/audit` by an admin. No token, header, request body or sample byte is ever stored.

Each new row carries `prev_hash`/`entry_hash` (SHA-256 over a canonical encoding of exactly the stored fields) and, since D31, `entry_mac`/`key_id` (HMAC-SHA-256 over the same bytes, from the audit key ring), appended inside one `BEGIN IMMEDIATE` transaction so concurrent writers produce one chain. Without the key, an attacker who recomputes every digest still fails at the MAC.

```bash
cd server
npm run audit -- head                      # id:hash — record it somewhere the DB writer cannot rewrite
npm run audit -- status [policy]           # rows, oldest/newest, size, growth, what a run would move
npm run audit -- compact [policy] [--apply] # archive a segment and hand the chain off (dry run by default)
npm run audit -- archives                  # every recorded archive segment
npm run audit -- verify                    # human output; exit 1 on the first break
npm run audit -- verify --no-archive       # presence only — says it did not read the archives
npm run audit -- verify --expect-head 412:<hash>
npm run audit -- verify --archive FILE --keyring RING   # offline: no database needed
npm run audit -- key status | key rotate   # ids only, never key material
```

**Retention is off by default and the server never deletes an audit row.** `audit_log`
grows for the life of the deployment and nothing prunes it at runtime; a documented policy
(`--older-than 30d` / `HATCHERY_AUDIT_RETENTION_DAYS`, `--max-rows N` /
`HATCHERY_AUDIT_RETENTION_MAX_ROWS`, always keeping `--keep-rows` — default 1 — live as the
anchor) is applied only by `npm run audit -- compact --apply`, a host-local operator action.
A compaction writes the archive first, the manifest last (last-writer-wins is never a
thing here), then deletes exactly that window in one `BEGIN IMMEDIATE` transaction that
re-checks it. A crash at any step resumes; a second run never double-archives or loses a
row. **Nothing is re-hashed** — the live rows keep their digests and MACs and the archived
rows keep theirs, which is the point. The archive is a projection of `audit_log` (no token,
header, body, sample byte or key material), `0600`, and never committed.

`verify` reports `segments` (live rows, archived rows, the archived tail and whether the
live chain's first `prev_hash` links to it), `archive` (`recorded`/`present`/`checked`/
`verified`, the manifest SHA-256, the join) and `archive_verified`. `assurance` still
describes the **live rows only** — compaction must not silently weaken the claim — so read
`assurance` and `archive_verified` together: a verifier that did not read the archive says
so and never claims otherwise. A missing archive, a tampered archive, a manifest hash
mismatch and a join mismatch each have their own classification and are breaks, not `ok`.
Growth is warned about, never enforced: `HATCHERY_AUDIT_WARN_ROWS` (default 500000) and
`HATCHERY_AUDIT_WARN_BYTES` (default 256 MiB) appear in `audit status`, the verify response
and the startup banner, and a failed append is counted in `audit_chain_meta` so a restart
no longer forgets it. See [`docs/AUDIT-RETENTION.md`](docs/AUDIT-RETENTION.md).

`GET /api/audit/verify?limit=5000&after=<id>&expect_head=<id>:<hash>&archive=full|presence` does the same over HTTP (admin-only, itself audited, bounded). It returns `ok`, `first_broken` (`forged`, `modified`, `deleted`, `inserted`, `unkeyed`, `unknown-key`, `truncated`, `replaced`, `unhashed`, `archive-missing`, `archive-mismatch`, `archive-modified`, `archive-truncated`, `archive-invalid`, `join-mismatch`), and — because a bare `ok` would overstate what was checked — `assurance` (`empty`/`unkeyed`/`mixed`/`keyed`), `coverage`, `key` (id and source, never material), `anchor` (`matches`, `found_in`, `head_at_anchor`), `segments`, `archive`, `archive_verified`, `growth`, and the persisted `append_failures_*` counters. The audit key comes from `HATCHERY_AUDIT_KEY` (64 hex), `HATCHERY_AUDIT_KEY_FILE` (0600, no symlink), or the generated `<db dir>/.audit-keyring` `0600` ring — the ring is authoritative once it exists. The database itself is created `0600`.

**CORS.** An explicit allow-list, not a reflection: the documented dashboard origin on `5173` (`localhost`, `127.0.0.1`, `[::1]`) plus comma-separated `HATCHERY_ALLOWED_ORIGINS`, matched exactly (`scheme://host[:port]`, no wildcards, no paths — invalid entries are named and ignored at startup). Credentials are never allowed, `Vary: Origin` is always sent, and a request with no `Origin` header (curl, the worker, the CLI) is unaffected. CORS is **not** authentication: an unlisted origin still reaches the API and still needs a token.

**Queue.** `POST /api/submit` writes the job through `hatchery submit --enqueue` and returns `status: "queued"`; nothing is spawned and the request does not wait. `POST /api/submit/:id/retry` re-queues. `GET /api/tasks/:id` reports the live job in a `queue` object and reconciles the job's terminal state onto the task row on read (ingesting the bundle when the job completed, recording the job's error when it failed). A **worker must be running** for jobs to execute: `hatchery worker`. The queue database is `data/queue.db` (override with `HATCHERY_QUEUE_DB`); the results root accepts `HATCHERY_RESULTS_ROOT`.

**Other defaults.** Binds `127.0.0.1`. `filePath` submissions are restricted to `samples/` and `uploads/` (override with `HATCHERY_ALLOWED_SAMPLE_ROOTS`), and uploaded filenames are reduced to a bare name. The CORS allow-list is extended with `HATCHERY_ALLOWED_ORIGINS`. The API database (`HATCHERY_DB_PATH`, default `data/hatchery.db`) holds the token store and the audit chain — treat it as a credential store, which is why it is created `0600` in a `0700` directory. Its audit key lives in `HATCHERY_AUDIT_KEY` / `HATCHERY_AUDIT_KEY_FILE` or the generated `<db dir>/.audit-keyring`; an unusable key stops the API from starting rather than downgrading the chain. Compaction archives land in `<db dir>/audit-archives/` (override with `--out`), and the growth warning thresholds are `HATCHERY_AUDIT_WARN_ROWS` (default 500000) and `HATCHERY_AUDIT_WARN_BYTES` (default 256 MiB). When the API needs a token, the dashboard's dev server can carry one: `HATCHERY_DASHBOARD_TOKEN=<token> npm run dev`. See [`SECURITY.md`](SECURITY.md), [`docs/API-SECURITY.md`](docs/API-SECURITY.md) and [`docs/AUDIT-RETENTION.md`](docs/AUDIT-RETENTION.md).

---

## Development

```bash
ruff check engine/ tests/ && mypy engine/ && pytest -q      # 795 tests (+ emulation tests when the extra is installed)
(cd server && npm run build && npm test)                    # 97 node tests (34 in D25/D29, 35 D30, 15 D31, 13 D32)
hatchery rules lint                                          # YARA gate
HATCHERY_E2E=1 pytest tests/test_dynamic_e2e.py -v            # really detonates (needs Docker)
HATCHERY_EMULATION_E2E=1 pytest tests/test_emulate_e2e.py -v  # really emulates (needs the emulation image)
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
                                                           ├──► manifest.json (D33, last)
                                                           └──► API ingest ──► SQLite ──► dashboard
```

When emulation is enabled, a Windows PE additionally goes through `engine/emulate/` → Speakeasy in a tier-probed container → `emulation-events.jsonl` (a separate stream) plus a top-level `emulation` section (`config`, `snapshots`, `capa_dynamic`) in `bundle/analysis.json`.

When triage is enabled, `engine/triage/` builds a **bounded, citable evidence set** from the bundle (stable `event:N` / `rule:...` / `ioc:...` / `capa:...` / `emulation:...` ids, sample text wrapped in an untrusted-data boundary), asks a local Ollama model under a versioned JSON-schema contract, grounds every citation against that evidence set, and writes a top-level `triage` section. The bundle is the single source of truth: triage patches `analysis.json` rather than living in a side file the API never reads.

When a run is replayed, `engine/replay/` locates and hash-verifies the original sample, shells out to the existing `submit` pipeline with the settings the bundle recorded (tier, detonation, emulation), and writes a `replay` section with the verdict, the deterministic/volatile signal diff and the reasons the replay is weaker than the original. Static signals are compared for equality; dynamic observations are reported as drift. The original bundle is never modified.

When a submission is queued, `engine/queue/` writes one row to a stdlib-SQLite `jobs` table and a worker claims it, runs the existing `submit` pipeline as a subprocess, and records the outcome. Claiming is atomic (`BEGIN IMMEDIATE`), concurrency is bounded, and a running job holds a lease that the worker renews; a dead worker's expired lease is recovered by the next worker and failed after `max_attempts` rather than left `running`. The bundle is the authority for completion. The API enqueues (it never spawns analysis) and projects the job's state onto its own `tasks` row on read.

---

## Roadmap

**Phase 0 — make it true.** ✅ *done in this revision.* Ten ship-blockers fixed (network never created, artifact paths wrong, seccomp blocking its own tracer, unbound name masking errors, exit code always zero, fake services never started, no ingest path so the dashboard was permanently empty, and more), the README rewritten to match reality, and the security defaults tightened.

**Phase 1 — an isolation boundary that holds.** ✅ *evasion instrumented as a first-class scored signal; a per-tier monitoring strategy named in every run; and the gVisor tier-2 boundary made real and wired — a runsc runtime, per-container OCI annotations that enable the Sentry trace, and a parser that turns it into `source="gvisor-sentry"` events and evasion scores. Verified end-to-end on a live gVisor detonation.* ⚠️ *host-side eBPF for tier 3 is designed and declared per run but not wired; `strace` remains the tier-3 fallback and the run says so.*

**Phase 2 — breadth.** Delivery-format intake is **largely done in this revision**: ZIP/OOXML Office, tar/gzip/bzip2/xz, HTML/SVG, Windows shell links (LNK), ISO9660/IMG images, PDF embedded files/JavaScript, legacy Office OLE/CFB compound files and RTF embedded objects are unpacked on one bounded intake path and each extracted child is hashed, classified and analysed statically — with OLE/CFB embedded VBA macros decompressed to source (MS-OVBA) and `\x01Ole10Native` packages carved out, and an RTF `\objdata` OLE payload recursed into the same OLE parser — while 7z, RAR and CAB are detected and reported as unsupported (never silently skipped) — see D19. **MISP/OpenCTI push is done as D20**: the CLI transports the run's single STIX 2.1 bundle to MISP's STIX 2.1 import or an OpenCTI TAXII 2.1 push collection, fail-closed and without persisting the token (wire format pinned; live instance untested). **Windows PE emulation is done as D21**: Speakeasy 2.0.0b6 runs in a container at the probed tier and extracts runtime configuration (C2 endpoints, user agents, mutexes, registry persistence, dropped files) with `capa_dynamic` over captured memory snapshots — declared, containerized and fail-closed, never sold as isolation. Extraction of the remaining archives (7z, RAR, CAB) is still ahead. The telemetry half is **done**: the ATT&CK mapping is rebuilt data-driven from a pinned **ATT&CK 19.2** dataset (the `Stealth`/`Impair Defenses` split, Detection Strategies and revoked-ID validation included), the bundle emits **OCSF 1.9.0 Detection Findings** and an **ATT&CK Navigator Layer v4.5**, tier-2 traces are attributed to the sample's process subtree, tier-2 in-guest artifacts are recovered copy-based, and candidate **Sigma rules** are emitted as generated drafts.

**Phase 3 — AI triage, done properly.** ✅ *(the layer is built)* Local (Ollama) behavioural triage with versioned prompt contracts, JSON-schema-validated output, grounding requirements and **fail-closed suppression**: every claim cites an evidence id that must exist in the run, and a verdict that cannot be grounded is INCONCLUSIVE. Sample-derived text is treated as hostile input inside an untrusted-data boundary, with an adversarial-string test in CI, because malware contains strings designed to steer an LLM's verdict. ✅ *(clustering)* `hatchery cluster` groups runs that look like the same campaign from a weighted similarity over what the engine already recorded, listing the shared features that justify each group and never naming a family — similarity is a lead, not attribution. ✅ *(MCP)* `hatchery mcp` exposes the engine as an MCP tool an agent can call (`submit_sample`, `get_report`, `get_iocs`, `triage_run`, `cluster_runs`), stdlib only over stdio. ⚠️ *What is not done: the report is behavioural, not literally function-level (mapping a claim to a specific function needs CFG reconstruction); technique associations the model proposes are validated as ids but not proven as the best association; clustering has no API/dashboard surface yet, and there is no fuzzy hashing or true code-reuse lineage extraction.*

**Phase 4 — product.** ⏳ *in progress.* The API now has **roles** (admin/viewer) and an append-only **audit log** rather than one shared secret (D25), and **Phase 4c** adds a token lifecycle, a CORS allow-list and a tamper-evident audit chain (D30); **deterministic replay** is built (D26): `hatchery replay <run_dir>` re-analyses a run and returns a reproducibility verdict, failing loudly when a deterministic static signal changed and reporting dynamic drift without failing; and the **durable queue and workers** are built (D27): `hatchery submit --enqueue` plus `hatchery worker` execute submissions asynchronously with atomic claims, leases, bounded concurrency and fail-closed recovery of a dead worker's job, while the API enqueues instead of spawning and reflects queue state on read; and the **sample store** is now content-addressed, encrypted at rest (AES-256-GCM, versioned envelope) and reference-aware (D28): `hatchery store status|verify|migrate|prune`, a worker that runs from the store after the original path is deleted, and a replay that is INCONCLUSIVE rather than a pass when a sample is purged. **Phase 4b** adds key lifecycle and recovery (D29): a key ring with per-blob key-id resolution, resumable atomic rotation and explicit retirement, plus SQLite-backup-API backups and a fail-closed restore that preserves job state and refuses to claim success while anything is undecryptable. **Phase 4d** makes the audit log finite without making it a lie (D32): a documented retention policy that is off by default and applied only by `npm run audit -- compact --apply`, a segment archived to a `0600` JSONL file plus a last-written manifest with the chain handed off so the join is provable, crash-resume at every step, concurrent appends that are never lost, verification that reports the segments and the archive state (a missing or tampered archive is a break, and `assurance` never silently drops because history moved), offline archive verification, and a disk-growth guard that warns in `audit status`, the verify response and the startup banner and never deletes. **Phase 4e** makes the result bundle self-describing and finite (D33): a deterministic SHA-256 manifest at the run root written last by every mutating stage (`submit`, `triage`, `push`, `replay`), `hatchery results verify|seal|status|prune`, an operator-recorded anchor that catches a rewrite of an artifact together with its manifest, an off-by-default retention policy that refuses to delete a run it cannot verify (rename-then-remove, crash-resumable), and a growth guard that warns and never deletes. **Phase 4f** makes the directory's conclusion include its nested units (D34): a nested replay with no manifest is `nested-unsealed` (`ok: false`, exit 1) and blocks retention by name, `hatchery results seal <root> --all` brings a whole corpus — nested legacy replays included — into the verifiable state depth-first and idempotently while leaving intact parent manifests byte-identical, `scripts/verify_manifest.py` is a stdlib-only verifier that runs the same code path so the recipient can check the claim without the analysis toolchain, `hatchery triage` accepts a run directory or its `bundle/` (CLI and MCP), and a contended sample store reports `store-busy` and exit 1 instead of a SQLite traceback. **D35** then closes the store's first-write race: the auto-generated key is published atomically (a fully written `0600` temporary is linked to `.sample-key`), so simultaneous first openers never read an empty key; the setup gate now runs four concurrent first submits against a fresh store. **Phase 4g** makes the analysis credible where it previously lied (D36/D37): the ELF analyzer normalises pyelftools' integer and enum-name header forms (the eager `:x` fallback aborted every ELF parse, and a string comparison hid `ET_DYN` PIE), an unreadable PCAP is a named error with the tshark reason instead of an empty capture, a PE's own `MZ` header is no longer an "embedded PE", and the packing rule measures the entropy its name promises — so a benign minimal PE scores clean. The fixture scorecard now records **0 known defects**. The manifest is a hash manifest, not a signature, and `results/` remains plaintext: signing and encryption are separate decisions. **Phase 4c** gives the API a credential lifecycle and a trustworthy record (D30/D31): named tokens with ids, roles, expiry and revocation stored as hashes (rotation without a restart, no secret in a response, a log or the database), an exact-match CORS allow-list instead of `origin: true`, and an append-only audit chain that is **keyed** (per-row HMACs from a rotatable local key ring) with a bounded verifier that names a forged, modified, deleted, inserted, unkeyed, truncated or replaced row, reports its own assurance, and can be anchored to a head recorded outside the database. Still ahead: KMS/HSM and escrow (the audit chain is keyed locally, not by a KMS or anchored to a remote log), per-user accounts/OIDC, scheduled rotation and compaction, multi-host stores and token databases, off-host archive shipping, encryption of the audit log and its archives, remote/cloud detonation, and shareable analysis URLs.

---

## Sources for the design decisions

CAPEv2, Joe Sandbox v44 (2026), VMRay, Firecracker and gVisor design docs, Kata Containers, Dirty Frag container-vs-microVM evaluation (2026), Datadog Security Labs on eBPF rootkits (2026), YARA-X 1.0 release and VirusTotal's migration, mandiant/capa v9.x releases, MITRE ATT&CK v18/v19 release notes, NIST SP 800-61r3 (2025), Microsoft Research Project Ire (2026), VirusTotal Code Insight, and the Microsoft DTDA paper on production LLM prompt contracts. Full citations are in [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

*Built by Raphael Main + Agent Mackenzie.*
