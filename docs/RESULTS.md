# Result bundles: integrity, retention and the growth guard (D33/D34)

This is the operator's guide to `results/<run>/` after Phases 4e–4f: what the
manifest proves, what it deliberately does not, how to seal and verify a run or
a whole corpus, how to anchor a delivery, what to send the recipient, and how
retention decides what may be deleted. The decision records are
[`DECISIONS.md`](DECISIONS.md) D33 (the manifest, the anchor and retention) and
D34 (nested units, the corpus seal, the client verifier and store-busy); the sample
store's own retention is D28
([`RETENTION.md`](RETENTION.md)) and the audit log's is D32
([`AUDIT-RETENTION.md`](AUDIT-RETENTION.md)). The clean-copy evidence is the
[transcript](#captured-transcript) at the bottom of this page.

## The shape of a run

```
results/<run>/
├── manifest.json          # D33: SHA-256 of every file below, written last
├── bundle/
│   ├── analysis.json      # the one source of truth (D4)
│   ├── events.jsonl
│   └── emulation-events.jsonl
├── sandbox/               # attacker-controlled artifacts, plaintext
├── delivery/              # children extracted from a container, plaintext
├── report.md, report.json
├── attack-navigator.json, ocsf.json, stix_bundle.json
├── push-<target>.json     # after `hatchery push`
└── replay-xxxx/           # a nested replay: its own manifest, its own unit
```

The manifest is at the **run root**, never inside `bundle/`: the API lists and
ingests `bundle/`, and replay, clustering and the MCP tools read it, so an extra
file in there would be a change to their input. It is invisible to every existing
reader.

## What the manifest is

A **hash manifest**, not a signature. It records the SHA-256 and size of every
file under the run root, plus provenance: format/version, run and task id,
`created_at`, `stage`, `sealed_at`, the HATCHERY version, and the sample's content
address and store reference. It contains **no** sample bytes, extracted strings,
IOCs, verdicts or counts — it describes files and provenance, never analysis
facts (that would be a second source of truth).

```json
{"algorithm":"sha256",
 "created_at":"2026-11-21T13:34:02.890004+00:00",
 "file_count":8,
 "files":[{"path":"bundle/analysis.json","sha256":"d9ec3abd…","size":5269},
          {"path":"bundle/events.jsonl","sha256":"e3b0c442…","size":0},
          {"path":"sandbox/strace/strace.log","sha256":"…","size":…}],
 "format":"hatchery.result-manifest",
 "hatchery_version":"0.1.0",
 "manifest_version":1,
 "run_id":"b860081a8960",
 "sample":{"sha256":"275a021b…","store_ref":"275a021b…"},
 "sealed_at":"2026-11-21T13:35:33.870426+00:00",
 "stage":"submit",
 "task_id":"b860081a8960",
 "total_bytes":14663}
```

The bytes are deterministic — UTF-8, sorted paths, `sort_keys=True`,
`separators=(",", ":")` and one trailing newline — so
`sha256(manifest.json)` is reproducible. Written temp + `fsync` + rename +
directory `fsync`, `0600`, and **last**: a crash before it leaves no manifest,
never a half-manifested run reported complete.

## What it proves, and what it does not

**Proves:** the run directory has not changed since the last HATCHERY stage that
touched it. Every stage that writes or mutates a run re-seals it — `submit`,
`triage`, `push`, `replay` — so a legitimate triage is not reported as tamper,
and `verify` prints which stage sealed the manifest and when. Since D34 the claim
also covers the **nested units the directory ships**: a `replay-xxxx/` with no
manifest makes the parent `nested-unsealed`, `ok: false`, exit 1.

**Does not prove:**

| Limit | What it means |
|:--|:--|
| Not signed, not MAC'd | Anyone who can write the run can rewrite an artifact **and** regenerate the manifest. Without an anchor that is undetectable. |
| Not encrypted | `results/` is plaintext: attacker-controlled artifacts, extracted strings, pcaps, strace logs. The manifest is integrity, not confidentiality. |
| Not an anchor by itself | Record `sha256(manifest.json)` when you deliver the run and check it with `--expect-manifest`. That is what catches a coordinated rewrite, and a deleted manifest is unambiguous. |
| No "unmodified since delivery" claim | After delivery, only the anchor says anything about later changes. |
| Copies of `bundle/` alone | A bundle copied without its manifest verifies as `unsealed`. Copy the run directory. |

## Verifying

```bash
hatchery results verify results/<run>                  # human output, exit 0/1
hatchery results verify results/<run> --json           # one object on stdout
hatchery results verify results/<run> --expect-manifest <sha256>
```

| State | `ok` | Exit | Meaning |
|:--|:--:|:--:|:--|
| `intact` | ✅ | 0 | manifest present, valid, and every file **and every nested unit** matches |
| `unsealed` | ❌ | 0 | the run itself has no manifest (a legacy run, or a deleted one). Never `ok`; does not fail a corpus |
| `broken` | ❌ | 1 | a break, with `classification` and `path` |

| Classification | What happened |
|:--|:--|
| `modified` | a file's bytes differ (same size) |
| `truncated` | a file is shorter than recorded |
| `missing` | a listed file is gone |
| `extra` | a file on disk is not listed |
| `symlink` | a symlink anywhere in the run, or a symlinked manifest; the target is never hashed |
| `manifest-invalid` | unreadable, malformed, inconsistent, traversal-bearing, or not a manifest for a HATCHERY run |
| `manifest-version` | a version this build does not understand |
| `manifest-missing` | `--expect-manifest` was given and there is no manifest |
| `replaced` | the manifest does not match the anchor |
| `nested-unsealed` | the run's own files match, but a nested replay unit has no manifest — `ok` false, exit 1, `path` is the nested directory (D34) |

The first break is deterministic (sorted by path), so two runs over the same tree
name the same break. `--json` is one object on stdout; diagnostics go to stderr.
A copied, renamed run verifies — the manifest records a run id but never compares
it to the directory name.

A **nested replay** is verified as its own unit and reported under
`nested_runs`. A nested *broken* unit keeps its own classification and its path
(`replay-xxxx/bundle/analysis.json`). A nested *unsealed* unit (an inconclusive
replay's directory, just `replay.json`) is `nested-unsealed`: the parent reports
`ok: false`, exit 1, names the nested directory as `path`, and the human output
prints a `nested replay <id>: unsealed` line. `--expect-manifest` is still
evaluated: `anchor.match: true` can sit beside `ok: false`, and an explicit
sentence says the anchor proves the parent manifest, not the whole directory.
If both a broken and an unsealed child exist, the broken child's classification
is reported first (it names the more specific break); every child is still listed.

## Sealing a legacy run — or a whole corpus

```bash
hatchery results seal results/<run>            # idempotent; prints the manifest sha256
hatchery results seal results/<run> --replace  # only when the change was deliberate
hatchery results seal results --all            # every run under a root, nested units first
hatchery results seal results --all --json     # per-run sealed/already/refused/ignored entries
```

`seal` makes a run written before this slice verifiable. A valid existing
manifest is returned **unchanged** (its hash printed, nothing rewritten). An
existing manifest that does not match the tree is **refused** — rewriting it
silently would hide exactly the tamper it exists to report. `--replace` rewrites
anyway, prints the old hash, and states that any anchor to it is void.

`--all` is the corpus operation, because “seal the corpus first” has to be one
command or nobody does it:

- **Depth-first.** A nested replay is sealed before its parent. Sealing the
  nested unit writes a manifest *inside* that directory, which the parent's
  manifest excludes by definition, so **the parent's manifest hash does not
  change** and an anchor recorded at delivery stays valid.
- **Idempotent and resumable.** A second invocation seals nothing and prints the
  same hashes (`already`). An interrupted batch is completed by running it again.
- **Per-unit reporting.** `sealed` and `already` carry the manifest sha256;
  `refused` carries the reason, classification and path; `ignored` covers hidden
  entries, `.deleting-*` strays, symlinks and directories that are not runs. A
  symlinked run is reported, never followed.
- **Exit codes.** 0 when nothing was refused, 2 when a run was refused (nothing
  about it is blessed), 1 on an operational error.
- **`--replace` is refused with `--all` (exit 2).** Re-sealing mismatches across a
  whole corpus would bless tamper everywhere it is found. Seal the one run
  deliberately, then re-run `--all`.

`triage` and `push` verify the *incoming* state before they touch a run. A run
that no longer matches its own manifest is not modified: the stage refuses and
tells you the classification and the path, so a later stage cannot launder an
out-of-band edit into a fresh manifest. A nested unit is its own unit and does
not block a legitimate triage of an otherwise intact run; `results verify` and
`seal --all` are where the directory's nested state is handled.

## The verifier you send with the run

```bash
python scripts/verify_manifest.py results/<run>
python scripts/verify_manifest.py results/<run> --expect-manifest <sha256>
python scripts/verify_manifest.py results/<run> --json
```

This is **“Python 3 and nothing else”**: no click, rich, YARA-X, capa or Docker,
no database, no `HATCHERY_*` environment. It puts the checkout root on
`sys.path` and calls the same `engine.results.manifest.verify_run`, so there is
exactly one implementation of the rules and the recipient's answer cannot drift
from `hatchery results verify`. Same classifications, states, exit codes (0
intact or unsealed, 1 broken, 2 usage) and JSON keys, plus `--expect-manifest`.

Send the script (or the same revision) with a copied **run directory** — not just
`bundle/`, which would verify as `unsealed`.

## Retention

Retention is **off by default** and applied only by an operator command. Nothing
in `submit`, the worker or the API deletes a run; there is no timer and no
background task.

| Knob | Meaning | Default |
|:--|:--|:--|
| `--older-than 30d` / `HATCHERY_RESULTS_RETENTION_DAYS` | delete runs sealed more than this long ago (`s`/`m`/`h`/`d`/`w` or seconds) | unset → no expiry |
| `--keep-last N` / `HATCHERY_RESULTS_KEEP_LAST` | always keep the newest N runs (the anchor) | `1`, minimum `1` |
| `--apply` | actually delete | dry run |
| `HATCHERY_RESULTS_WARN_RUNS` | warn at this many runs (`0` disables) | `2000` |
| `HATCHERY_RESULTS_WARN_BYTES` | warn at this total size (`0` disables) | `10 GiB` |

```bash
hatchery results status                                   # count, bytes, oldest/newest, unsealed counts, strays, growth
hatchery results prune --older-than 30d                   # dry run: exactly what would go, and why
hatchery results prune --older-than 30d --keep-last 5     # keep five, delete older than 30 days
hatchery results prune --older-than 30d --keep-last 5 --apply
```

- **A run is the unit.** A nested replay goes with its parent; every decision
  records how many nested runs it contains.
- **The anchor is never deleted.** `--keep-last 0` is clamped to 1, and a policy
  that would remove every run leaves the newest with `reason: kept-last` and
  reports `clamped: true`.
- **Fail closed.** A run with no manifest, an invalid manifest, an unparseable
  `analysis.json` **or an unsealed nested unit** is never deleted: `--apply`
  refuses the whole plan, deletes nothing and exits 2. The decision and the
  refusal carry `reason: nested-unsealed` (distinct from `manifest-invalid`) with
  the nested path. Seal the corpus first
  (`hatchery results seal <results-root> --all`), then prune. A directory that is
  not a run at all is reported as ignored.
- **Age is the last stage's `sealed_at`**, not the directory mtime.
- **Rename, then remove.** `<run>` becomes `<run>.deleting-<ts>` before the tree
  is removed, so a reader mid-replay gets a clean `not-found` instead of a torn
  tree. A crash leaves a stray; the next prune completes it (`resumed_strays`) and
  `status` reports it in the meantime.
- **Two prunes serialise** on `results/.results.lock`; the second reports
  `results-locked` and deletes nothing.
- **Every prune appends one line** to `results/.prune-log.jsonl` (`0600`,
  append-only). It is an operator convenience, **not** tamper-evident: the audit
  chain covers API actions, not local CLI maintenance.

### The sample-store interaction (D28)

`store prune` decides from a fresh scan of `<results>/<run>/bundle/analysis.json`
(`sample.sha256`, replays one level deeper) and every queued/running job. Pruning a
run therefore releases a sample that only that run referenced — and never releases
one that another run or a queued job still needs. `store prune` is unchanged; the
scan is the authority.

A sample referenced only by run A becomes prunable after A is pruned. A sample
referenced by run B or by a queued/running job stays protected, whatever happens
to A.

## Replay and the manifest

`hatchery replay` checks the source run's manifest **before** it loads the bundle
or locates the sample:

- matching → the replay proceeds and `bundle_manifest.state: "verified"` (with the
  manifest hash and stage) is recorded in `replay.json` and the replayed bundle;
- **not** matching → INCONCLUSIVE naming the classification and the file. Nothing
  is submitted: a verdict about bytes that are not the run is a verdict about
  fiction. `replay.json` is still written with the reason;
- absent → the replay proceeds, the verdict is unchanged, and
  `bundle_manifest.state: "unsealed"` is recorded with a limitation line;
- `--require-manifest` (off by default) turns `unsealed` into INCONCLUSIVE for
  operators who seal everything.

The verdict is about reproducibility; the seal state is a separate field.

## Common operations

```bash
# Deliver a run: seal it if it predates the manifest, then record the anchor.
hatchery results verify results/<run>
hatchery results seal results/<run>            # prints manifest sha256; idempotent
hatchery results verify results/<run> --expect-manifest <sha256>

# Bring an existing corpus (nested legacy replays included) up to date, once.
hatchery results seal results --all
hatchery results seal results --all --json | jq '.counts'

# Send the run and the verifier: Python 3 and nothing else.
python scripts/verify_manifest.py /tmp/delivery/<run> --expect-manifest <sha256>

# Investigate a break before you trust anything downstream.
hatchery results verify results/<run> --json | jq '{classification, path, nested_runs}'

# Growth: look before you prune.
hatchery results status
HATCHERY_RESULTS_WARN_RUNS=5000 hatchery results status

# Retention: dry run, read the reasons, then apply.
hatchery results prune --older-than 30d --keep-last 5
hatchery results prune --older-than 30d --keep-last 5 --apply

# A crashed prune left a stray: the next run finishes it.
hatchery results status | grep stray
hatchery results prune --older-than 30d --apply
```

## What was not verified

- **The manifest is unsigned.** An attacker with write access to the run who
  rewrites an artifact *and* regenerates the manifest is caught only by an anchor
  recorded elsewhere. This is stated in the same words as D31/D32 rather than
  claimed away.
- **Sealing a corpus is not an integrity audit.** `seal --all` refuses a run whose
  existing manifest does not match, but a run that was already unsealed when it
  was tampered with has no old manifest to compare against; the anchor covers
  changes from delivery onward. A nested unit is verified one level deep (the
  layout HATCHERY writes); a replay inside a replay is not walked further.
- **The client verifier trusts its own checkout.** Send the script with the run
  (or the same revision). A verifier from a different revision that does not
  understand a manifest version refuses it as `manifest-version` rather than
  approximating it.
- **Results are not encrypted at rest.** `results/` is plaintext by design.
- **A run on different storage.** `fsync` and rename semantics on a network share
  or a different filesystem were not exercised.
- **A run directory modified while a prune runs.** Rename-then-remove means a
  reader sees the run or a clean `not-found`, never a torn tree; that is mitigation,
  not proof — nothing stops an unrelated process writing into the tree.
- **Windows ACLs.** The `0600`/`0700` posture is POSIX.
- **A root attacker** who can rewrite the run, the manifest and every copy of the
  anchor is out of scope. **Clock skew** moves the `--older-than` boundary; it
  cannot corrupt a bundle.
- **A manifest format change mid-stream** is refused (`manifest-version`), not
  migrated.
- **A bundle copied without its manifest** verifies as `unsealed`, which is the
  honest answer rather than a pass.
- **Store contention longer than 60 s.** Concurrent openers retry the WAL pragma
  within the existing timeout, then fail as `store-busy` with exit 1. Nothing is
  queued or serialised beyond SQLite's own locking; a pathological case is a
  retry, not a success.

## Captured transcript

Clean copy of the repository at commit `e64ca71` (the D33 code+tests commit), with
no `.venv`, `node_modules`, `data/`, `results/`, `uploads/` or caches. The only
deviation from the literal protocol is the interpreter: this host has no
`python3.12` on `PATH` and `python3` is 3.15 (excluded by `requires-python`), so
Python 3.12 is invoked through the interpreter uv had already installed
(`cpython-3.12.14`); `python -V` in the transcript confirms 3.12.14. A uv venv
ships no pip, so `python -m ensurepip --upgrade` ran first.

```text
# HATCHERY Phase 4e — clean-copy verification transcript

Captured: 2026-11-21T13:46:00Z (UTC)
Source: `git archive e64ca71` (the D33 code+tests commit) extracted into a fresh
        directory, with no `.venv`, `node_modules`, `data/`, `results/`,
        `uploads/` or caches in the archive. `git status --short` was empty
        before the archive was taken.
$ uname -srm; sw_vers
Darwin 27.2.0 arm64
ProductName:		macOS
ProductVersion:		27.2.1
BuildVersion:		26B131

$ python -V; node -v; npm -v
Python 3.12.14
v26.13.0
12.2.2

$ python -m pip show cryptography | grep -E '^(Name|Version)'
Name: cryptography
Version: 50.0.2

$ python -m pytest -q
..........                                                               [100%]
854 passed, 17 skipped, 3 xfailed in 28.28s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
(manifest verified; the pcap fixtures are the last rows)
ok       tests/fixtures/acceptance/replay/empty.pcap
ok       tests/fixtures/acceptance/replay/malformed.pcap

$ python scripts/verify_fixtures.py
capa Python API failed: module 'capa' has no attribute 'main'
HATCHERY fixture verification
manifest: tests/fixtures/acceptance/manifest.json (10 fixtures)
python:   3.12.14 (/private/tmp/hatchery-phase4e-clean/.venv/bin/python)
capa:     not on PATH
tshark:   /opt/homebrew/bin/tshark

fixture/hashes               PASS          10 files match the manifest
static/eicar                 PASS          HATCHERY_EICAR_TestFile; 5 rule files loaded
static/negative-control      PASS          0 matches with 5 rule files loaded
static/benign-pe-structure   PASS          PE32+ x64 (AMD64); Windows CUI (Console)
static/benign-pe-yara        KNOWN-DEFECT  HATCHERY_Packing_Generic_HighEntropy, HATCHERY_Suspicious_HexStrings on a benign PE (rule calibration)
static/benign-elf-fixture    PASS          independently parsed: EM_X86_64 ET_EXEC
static/benign-elf-analyzer   KNOWN-DEFECT  uploader=ELF, analyzer error: ELF parsing error: Unknown format code 'x' for object of type 'str' (ELF parser)
static/packer-pe             PASS          no packer indicators, no error
static/packer-elf            PASS          inapplicable with an explicit error: Failed to parse PE: 'DOS Header magic not found.'
detector/capa                PASS          unavailable (Python) with preserved reason: capa Python API not usable: module 'capa' has no attribute 'main'
replay/strace-timestamp      PASS          9 events, tree {'1000': [1001]}, 1 connection
replay/strace-pid-first      PASS          9 events, tree {'1000': [1001]}
replay/file-events           PASS          {'total_events': 5, 'created_files': 1, 'modified_files': 1, 'deleted_files': 1}
replay/pcap-one-packet       PASS          1 packets, 1 connections
replay/pcap-empty            PASS          0 packets, 0 connections
replay/pcap-malformed        KNOWN-DEFECT  unreadable capture reported as an empty result (PCAP backend)

13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed

$ ruff check engine/ tests/ scripts/
All checks passed!
$ mypy engine/
Success: no issues found in 86 source files
$ hatchery rules lint
Rule lint passed: 5 files, 0 unaccepted warning(s), 1 accepted

$ scripts/verify_setup.sh
HATCHERY baseline verification
repo:   /tmp/hatchery-phase4e-clean
python: Python 3.12.14 (/tmp/hatchery-phase4e-clean/.venv/bin/python)
node:   v26.13.0 / npm 12.2.2

PASS  python/package-installed           0.1.0
PASS  ports/free                         API (3002) and dashboard (5173) are available
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  store/encrypted-at-rest            content-addressed AES-256-GCM blob, 0600, no plaintext
PASS  results/manifest-sealed            run root manifest, 0600, hashes verified, stage submit
PASS  results/tamper-detected            modified artifact named with its path, exit 1
PASS  results/prune-keeps-anchor         dry-run order applied, anchor kept, 0600 prune log
PASS  server/npm-ci                      dependencies installed from the lockfile
PASS  server/build                       production build succeeded
PASS  dashboard/npm-ci                   dependencies installed from the lockfile
PASS  dashboard/build                    production build succeeded
PASS  api/compiled-start                 node dist/index.js answered /api/health
PASS  api/enqueue                        task 3ca03b3d-473 queued (no subprocess held open)
PASS  api/restart-durability             task survived an API restart
PASS  worker/executes-job                worker drained the queue and exited 0
PASS  worker/store-backed-job            job records a content address and completed from it
PASS  api/ingest-after-worker            completed task has the expected hash and static results
PASS  api/db-permissions                 API database is 0600 (audit log and token hashes)
PASS  api/audit-chain-keyed              audit chain verifies as keyed, every row MAC'd
PASS  api/audit-key-announced            startup names the audit key id and never the material
PASS  api/audit-compaction               segment archived 0600, manifest written last, chain handed off
PASS  api/audit-archive-verified         live chain verifies across the boundary; archived rows were read
PASS  store/key-rotation                 every blob re-wrapped; verify passes on the new active key
PASS  store/backup-restore               manifest hashes every blob; restored job ids and samples verify
PASS  dashboard/dev-server               http://localhost:5173/ returned 200
PASS  dashboard/api-proxy                /api/health proxied to the API
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged

RESULT: baseline verified

$ (cd server && npm ci && npm run typecheck && npm run build && npm test)
ℹ tests 97
ℹ pass 97
ℹ fail 0

$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
ℹ tests 3
ℹ pass 3
ℹ fail 0

$ (cd dashboard && npm ci && npm run build)
dist/assets/index-CwBji8IX.js   272.30 kB │ gzip: 84.69 kB
✓ built in 515ms

=== result bundles: live commands against temporary roots ===

$ hatchery submit samples/eicar.com --no-sandbox -o results/run-a
╭──────────────────────────── ✅ Analysis Complete ────────────────────────────╮
│ Task ID: b71cbaea856f                                                        │
│ Status: completed                                                            │
│ Results: results/run-a                                                       │
│ Manifest: 96c98e07f1d50f48e0a639e3778bda8402ec64757de23b001ac0f642c0f185bd   │
╰──────────────────────────────────────────────────────────────────────────────╯
  Verify or deliver this run with: hatchery results verify results/run-a

$ hatchery results verify results/run-a --json   # exit 0, intact, stage submit
{'ok': True, 'state': 'intact', 'stage': 'submit', 'file_count': 8, 'total_bytes': 14634, 'manifest_sha256': '96c98e07f1d50f48e0a639e3778bda8402ec64757de23b001ac0f642c0f185bd'}
exit=0

$ shasum -a 256 results/run-a/manifest.json; stat -f "%Lp" results/run-a/manifest.json
96c98e07f1d50f48e0a639e3778bda8402ec64757de23b001ac0f642c0f185bd
600

$ head -c 220 results/run-a/manifest.json
{"algorithm":"sha256","created_at":"2026-11-21T13:45:54.904055+00:00","file_count":8,"files":[{"path":"attack-navigator.json","sha256":"58d08e74447157d3a52c3daccc091cef5b05768aeb23bab195160bf671b51d29","size":1125},{"pat…


# delivery: record the anchor; a recipient checks it
$ hatchery results verify results/delivered --expect-manifest $ANCHOR
exit=0

# a legitimate stage changes a file and re-seals: the run still verifies
after triage: exit=0
stage: triage | state: intact

# rewrite an artifact AND regenerate the manifest (the documented limit)
unanchored: exit=0 (internally consistent)
anchored:   exit=1
classification: replaced | path: manifest.json

# one modified byte names the file
exit=1
classification: modified | path: bundle/analysis.json

# a legacy run (no manifest) is unsealed, never ok; seal is idempotent
verify: exit=0
state: unsealed | ok: False
seal 1: written = True 2c825e7d641a82be
seal 2: written = False 2c825e7d641a82be

# retention: one 30-day-old run, one anchor; the dry run is the plan
$ hatchery results status --json --results results-prune
runs: 2 | oldest: run-old | newest: run-new | growth warned: False | enforced: False
$ hatchery results status --older-than 10d --keep-last 1 --json --results results-prune
a prune would remove: ['run-old'] | anchor: run-new
$ hatchery results prune --older-than 10d --keep-last 1 --json --results results-prune   # dry run
applied: False [('run-old', 'expired'), ('run-new', 'not-expired')]
$ ls results-prune
run-new
run-old
$ hatchery results prune --older-than 10d --keep-last 1 --apply --json --results results-prune
removed: ['run-old'] | bytes freed: 16033 | refused: 0 | clamped: False
$ ls results-prune; stat -f "%Lp %N" results-prune/.prune-log.jsonl; tail -c 240 results-prune/.prune-log.jsonl
run-new
600 results-prune/.prune-log.jsonl
 "argument"}}, "refused": [], "removed": [{"bytes": 16033, "nested_runs": 0, "run_id": "run-old"}], "resumed_strays": [], "root": "/private/var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T/hatchery-d33-demo.rva0bN/results-prune", "runs": 2}


# a policy that would delete every run is clamped: the anchor survives
keep_last: 1 | clamped: True | removed: [] | anchor: run-new

# an unsealed run blocks --apply (fail closed, nothing deleted)
exit=2
blocked: True | refused: ['no-manifest'] | removed: 0

# a crashed delete is a stray; status reports it and the next prune completes it
strays: [('run-new.deleting-20261121T000000Z', 'deleting-in-progress')]
would resume: ['run-new.deleting-20261121T000000Z']

# the sample store composes: a run still references the sample, so it is kept
deleted: 0 | kept: 1 | reason: referenced

demo root: /var/folders/zv/n4210phd6_d5lqqfx462c9gw0000gn/T//hatchery-d33-demo.rva0bN

=== repository state after every gate ===
(clean: no repository data/, results/, uploads/ or samples/ file was created)
```
