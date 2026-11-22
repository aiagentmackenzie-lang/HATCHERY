# Baseline verification

Verified **22 November 2026** on top of revision `2d60c69` plus D35 (the first store key
is published atomically; Phase 4f — nested-unit verification, corpus seal, client
verifier and the store-busy fix — is D34). The
D33 baseline was `e64ca71`. The D28
store baseline was `be9386d`, whose clean-copy transcript is in
[`RETENTION.md`](RETENTION.md#captured-transcript); the D29 transcript is in
[`BACKUP.md`](BACKUP.md#captured-transcript); the D30/D31 transcript is in
[`API-SECURITY.md`](API-SECURITY.md#captured-transcript); the D32 transcript is in
[`AUDIT-RETENTION.md`](AUDIT-RETENTION.md#captured-transcript); the D33 transcript is in
[`RESULTS.md`](RESULTS.md#captured-transcript), and the D34 transcript is at
[`RESULTS.md`](RESULTS.md#captured-transcript-d34). The
detector scorecard is unchanged from
`4b48490`.

This document is evidence, not a roadmap. It records what a clean checkout can
do today, the exact acceptance inputs, and the defects that remain. Product
decisions live in [`DECISIONS.md`](DECISIONS.md).

## Toolchain verified

| Item | Value |
|---|---|
| Host | macOS 27.2.1, arm64 |
| Python | 3.12.14 (3.13/3.14 are in the CI matrix; **3.15 is excluded** because capa's `python-flirt` dependency has no wheel) |
| Node | 22 (CI) and 26.13.0; npm 10 and npm 12 |
| Detectors | yara-x 1.24.0, pyelftools 0.33, flare-capa 10.0.0 CLI (no ruleset installed) |
| Replay tools | tshark 4.6.9 |

## What is verified

- A clean copy with no `.venv`, `node_modules`, `data/`, `results/`, `uploads/`
  or caches installs with `pip install -e ".[dev]"`, builds the server and
  dashboard, and passes the full Python suite: **880 passed, 17 skipped,
  3 xfailed** (was 875 at D34; 5 tests cover atomic key publication: a loser of
the first-key race uses the winner's key, an existing key is never overwritten
and leaves no temporary, the final name is linked only after the bytes are
complete and `0600`, a reader waits out an older create-then-fill writer, and a
permanently empty key file is a named `key-invalid`). `ruff` is clean and
`mypy engine/` reports no issues in **86 source files**.
- **The server suite is 97 node tests, 0 failing** (was 84 at `511a978`; 35 cover
  token lifecycle, CORS and the D30 audit chain, 15 cover D31 keying, key sources,
  anchoring and the file posture, and 13 cover D32 compaction: cross-segment
  verification, offline archive tamper detection, crash-resume, a concurrent append
  burst during a compaction, the growth guard and the failed-append path). The compiled
  server is built first — the tests import from `server/dist/`. The 3 cross-language
  queue tests (`node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs`) also
  pass, and the dashboard builds.
- `tests/fixtures/acceptance/` holds deterministic inputs (checked in, generated
  from byte templates, no compiler or download) with a manifest of SHA-256 and
  expected outcomes. `--check` fails if either the bytes or the expectations
  drift.
- The fixture scorecard is **13 passed, 0 failed, 3 known defects**. It
  distinguishes a genuine match (EICAR), a completed scan with zero findings
  (negative text with rules loaded), and a detector that could not run (capa
  unavailable, with its exit code and stderr preserved).
- `scripts/verify_setup.sh` exercises the normal entry points against temporary
  state: **32 passed, 0 failed** (was 19/0 at D28; 21 at D29/D30; 24 at D31, which added
  `api/db-permissions`, `api/audit-chain-keyed` and `api/audit-key-announced`; 26 at D32,
  which added `api/audit-compaction` and `api/audit-archive-verified`; 29 at D33, which
  added `results/manifest-sealed`, `results/tamper-detected` and
  `results/prune-keeps-anchor`; D34 adds `results/seal-corpus` and
  `results/client-verifier`; D35 adds `store/first-key-race`).
  - CLI submission from a non-repo directory produces a bundle with the expected
    SHA-256 and the EICAR rule.
  - The compiled API enqueues instead of holding a subprocess; the task survives
    an API restart; `hatchery worker --once` executes the job; reading the task
    ingests the bundle and exposes the expected hash and static results.
  - The dashboard serves on **5173** (matching the README and the API banner)
    and proxies `/api/health`.
  - **The sample store is encrypted at rest (D28).** The submitted sample is a
    content-addressed AES-256-GCM envelope, `0600`, no plaintext appears anywhere
    in the store directory, and the bundle records the store reference.
  - **The queued job records a content address** and the worker completed it from
    that copy (`sample_store_ref == sample_sha256`), not from the upload path.
  - **Key rotation re-wraps every blob (D29).** `store key rotate` completes on
    one active key and `store verify` passes; the status output reports per-key
    blob counts and `rotation_complete`.
  - **A backup restores (D29).** The manifest is written last, every blob hash
    matches, `--include-key` is `0600`, a restore into a temporary root verifies,
    and the restored queue keeps its job ids.
  - **A submitted run is sealed and verifies (D33).** The CLI's run has a `0600`
    `manifest.json` at the **run root** (not in `bundle/`) that hashes every file,
    `hatchery results verify` reports `intact` at `stage: submit` with the manifest
    hash it recomputed, and appending one byte to an artifact is `modified` at that
    exact path with exit 1.
  - **Retention keeps the anchor and records the decision (D33).** Two sealed runs
    (one re-stamped 30 days old) pruned with `--older-than 0s --keep-last 1 --apply`
    remove exactly the expired one, leave the anchor run intact, and append a `0600`
    `.prune-log.jsonl` line saying `applied: true`.
  - **A corpus seals depth-first and anchor-safely (D34).** One root holds a run with
    a legacy nested replay, an already-sealed run and a tampered run, plus a
    `.deleting-` stray, a non-run directory and a symlinked run. `results seal --all`
    seals the two unsealed units (nested first), reports the intact run unchanged, exits
    2 for the tampered one without blessing it, ignores the strays, never follows the
    symlink, and leaves the intact parent's manifest hash byte-identical.
  - **The recipient's verifier agrees with the CLI (D34).**
    `scripts/verify_manifest.py` reports a copied run `intact` outside the checkout with
    a nonexistent sample store, and a modified run `modified` at `bundle/events.jsonl`
    with exit 1 — the same conclusion as `hatchery results verify`.
  - **A compacted audit log verifies across the boundary (D32).** A real segment is
    archived `0600` with the manifest written last, the live chain hands off to the
    archived tail, and `verify` reads the archives and reports a proven join with the
    same `keyed` assurance for the live rows.
  - The repository's databases, results, uploads and every file under `samples/`
    are checksummed before and after and must be unchanged.

### Acceptance inputs

| Fixture | Expected outcome |
|---|---|
| `samples/eicar.com` | `HATCHERY_EICAR_TestFile` |
| `tests/fixtures/acceptance/benign/negative.txt` | 0 matches with rules loaded |
| `tests/fixtures/acceptance/benign/benign_pe.exe` | valid PE32+ x64; two recorded rule matches (see defects) |
| `tests/fixtures/acceptance/benign/hello.elf` | independently valid ELF64 x86-64 `ET_EXEC` (see defects) |
| `replay/trace_timestamp.log`, `trace_pid_first.log` | 9 events, process tree `1000 -> 1001`, 1 connection each |
| `replay/file_events.log` | 5 events: 1 created, 1 modified, 1 deleted |
| `replay/one_packet.pcap` | 1 packet, 1 connection (`tshark`) |
| `replay/empty.pcap` | 0 packets, no error |
| `replay/malformed.pcap` | recorded defect: reported as empty |

The manifest records the SHA-256 of each input; the generator reproduces them
byte-identically.

## Known defects on this baseline

| Defect | Evidence | Effect |
|---|---|---|
| Rule calibration | A benign one-section PE matches `HATCHERY_Suspicious_HexStrings` (its own MZ header) and `HATCHERY_Packing_Generic_HighEntropy` | Both are declared low severity, but a clean PE cannot score clean |
| ELF parser | `ELFAnalyzer` raises `Unknown format code 'x' for object of type 'str'` on pyelftools 0.33 enums | Valid ELF input gets no metadata; the fixture is independently validated so the parse failure is attributable |
| PCAP backend | An unreadable capture yields 0 packets and an empty `errors` list | Indistinguishable from a valid empty capture |

Each is pinned by a strict `xfail` in `tests/test_acceptance_fixtures.py` and a
`KNOWN-DEFECT` row in the scorecard. Fixing one makes the test fail until the
manifest, expectation and this document are updated — the baseline cannot drift
silently.

## Not covered by this baseline

Docker detonation, the gVisor tier, Windows PE emulation, replay comparison,
LLM triage, MCP, STIX push, campaign clustering and the sample store's
key/retention semantics have their own suites and CI jobs. The API's credential
lifecycle, its CORS allow-list and the audit hash chain are covered by the server
suite and [`API-SECURITY.md`](API-SECURITY.md) (D30). This baseline is about
installation, packaging, normal entry points and static acceptance inputs; it
does not re-certify those features.

### Known gaps introduced or inherited by D35

| Gap | What it means |
|:--|:--|
| The previous baseline was a green sample | D34 recorded 875 passed, and the same concurrency test failed on the next session's first run (2/12 reproduction). A passing distributed-timing test is evidence of a passing run, not of the absence of a race; the atomic publication, not the green count, is what closed it. |
| Key publication assumes a local POSIX filesystem | `link(2)` is atomic within one directory. A network filesystem with weaker semantics was not exercised, and Windows is unverified, as before. |
| A crash after the link leaves a duplicate temporary | `store reconcile` removes `.tmp-key-*` after its grace period; until then a second `0600` copy of the key exists in the store directory. Same exposure as the key itself. |
| A permanently empty legacy key file blocks a store | A reader waits 2 s, then fails `key-invalid` with the path and the two remedies. It never invents a key, so an operator who cannot restore the original must accept that the blobs are unreadable. |

### Known gaps introduced or inherited by D34

| Gap | What it means |
|:--|:--|
| Sealing a corpus is not an integrity audit | `seal --all` refuses a run whose existing manifest does not match, but a run that was already unsealed when it was tampered with has no old manifest to compare against. Sealing records the current bytes as the claim; only a delivery-time anchor covers changes after that. |
| A nested unit is verified one level deep | A nested replay is its own run and is verified as such; a replay nested inside a replay is not walked further. The on-disk layout HATCHERY writes is one level, and the verifier says what it checked rather than implying infinite depth. |
| The client verifier trusts the checkout it is shipped in | `scripts/verify_manifest.py` imports `engine.results.manifest` from its own checkout. Send the script with the run (or the same revision); a verifier from a different revision may understand a different manifest version — which it will refuse as `manifest-version`, not silently accept. |
| `--all` is a local path operation | It seals this host's results root. A corpus on another machine or a network share is not consulted, and `fsync`/rename semantics there were not exercised. |
| A symlinked run is skipped, not sealed | `seal --all` reports it under `ignored` and never follows it. An operator who points a symlink at a run must seal the target path deliberately. |
| Store busy is retried, not queued | Concurrent openers retry the WAL pragma/schema setup within 60 s. A pathological contention longer than that fails with `store-busy` and exit 1; the operator retries. Nothing is queued or serialised beyond SQLite's own locking. |

### Known gaps introduced or inherited by D33

| Gap | What it means |
|:--|:--|
| The manifest is not signed and not MAC'd | It is a hash manifest. An attacker with write access to the run who rewrites an artifact **and** regenerates the manifest is caught only by an anchor recorded elsewhere (`results verify --expect-manifest`). Without an anchor, a coordinated rewrite verifies as `intact`. D1/D2's reasoning is in D33. |
| `results/` is not encrypted at rest | It holds attacker-controlled artifacts (extracted strings, delivery children, pcaps, strace logs) in plaintext, by design: every reader is path-based. The manifest is integrity, not confidentiality. Encrypting results is a separate decision with its own key lifecycle. |
| Retention is an operator action | Nothing in submit, the worker or the API deletes a run and there is no timer. An operator who never runs `results prune --apply` gets a growth warning and an unbounded corpus. A run with no manifest (a pre-D33 corpus, or one written mid-crash) blocks `--apply` entirely until it is sealed. |
| The prune record is not tamper-evident | `results/.prune-log.jsonl` is `0600` and append-only, but it is an operator convenience: the audit chain covers API actions, not local CLI maintenance (the same boundary D28/D29 have). |
| A run directory modified during a prune | Rename-then-remove means a reader sees the run or a clean `not-found`, never a torn tree; that is mitigation, not proof. Nothing stops an unrelated process writing into the tree. |
| No off-host or multi-host retention | The pruner sees this host's results root only. A bundle on another machine is neither pruned nor consulted — and a reference there does not protect a sample from `store prune` unless the results root is in the scan. |
| Storage and platform assumptions | `fsync`/rename on a network share or a second filesystem was not exercised; Windows ACLs are unverified (the `0600` posture is POSIX). A root attacker and clock skew are out of scope, as before. |
| One manifest format version | A newer manifest version is refused (`manifest-version`), not migrated. A `bundle/` copied without its manifest verifies as `unsealed` — honest, not a pass. |

### Known gaps introduced or inherited by D30

| Gap | What it means |
|---|---|
| The audit chain is keyed **locally** | HMAC-SHA-256 from a local key ring (D31). A database-only attacker cannot forge a row, but an attacker who can also read the key file — which by default sits beside the database — can. `HATCHERY_AUDIT_KEY_FILE` outside the data directory is the stronger posture; the startup banner says so. No KMS/HSM and no remote signer. |
| Completeness needs an anchor | A truncation that also rewrites the stored head, and a restored older database, are internally consistent. Only a head recorded outside the database detects them (`npm run audit -- head` → `verify --expect-head`). Without that procedure, the verifier reports `ok` on a shortened log and says nothing false — but nothing protective either. |
| Audit key rotation only moves forward | Old keys stay in the ring (bounded at 32) so history verifies; there is no retirement, because removing a key would un-authorise the rows it MAC'd. A ring at the 32-key limit must be archived and restarted deliberately, which is not automated. |
| The append-failure counter is per process | `append_failures_since_start` is in memory. The **total** is persisted in `audit_chain_meta` (D32) so a restart no longer forgets it, but the write that records the failure can fail for the same reason the append did — `append_failures_persisted: false` says the total is understated and the server log is the record. |
| Pre-D30/D31 rows are not covered | The migrations do not backfill. Rows written before the chain existed keep `NULL` hashes (reported as `legacy`), and rows written between D30 and D31 keep `NULL` MACs (reported as `unkeyed`/`mixed`, never upgraded in the telling). |
| A failed audit append is invisible to the chain | `recordAudit` never throws (D25). A write that fails before it happens is logged and the request is answered; the chain can only see rows that exist. |
| Single-host token store | Tokens and the chain live in one SQLite file. There is no multi-host token database, no propagation and no coordinated rotation across hosts; the CLI and the server sharing the file (WAL + a 5 s busy timeout) is the tested case. |
| No create endpoint | Token creation is `npm run token -- create` on the host. An admin who is only reachable over HTTP cannot mint a token; that is deliberate (a secret must not cross the wire), but it is an operational constraint. |
| CORS is not authentication | An unlisted origin is prevented from *reading* a response by the browser; it still reaches the API and still needs a token. No browser matrix was run. |
| The API database is a credential store | `HATCHERY_DB_PATH` (default `data/hatchery.db`) holds the token hashes and the audit chain; it is created `0600` in a `0700` directory (D31) and needs the same care as the sample-store key. It is in `.gitignore` (`data/`), but nothing backs it up automatically. Windows ACLs are not verified. |
| Audit retention is an operator action | `audit_log` never shrinks on its own (D32). Nothing compacts it, nothing schedules a compaction, and nothing deletes an archive; an operator who never runs `npm run audit -- compact --apply` gets a growth warning and an unbounded log. Pre-D30 rows are never archived. |
| Audit archives are owner-readable, not encrypted | The archive and manifest are `0600` and contain exactly the `audit_log` columns plus key **ids** — no token, header, body, sample byte or key material — but they are not encrypted at rest and the manifest is not signed. An archive replaced wholesale together with its manifest is caught by the tail recorded in `audit_chain_meta`, against a live database you still trust. There is no off-host shipping and no multi-host story. |
| Compaction under a second writer is bounded by the write lock | Concurrent *appends* during a compaction are tested with a real burst; a concurrent *compaction* is refused by the window re-check under `BEGIN IMMEDIATE`, but two racing `compact` processes are not separately exercised. An archive on a different filesystem or a network share (`fsync`/rename semantics) was not verified. |
| The dashboard has no auth flow | The bundled dashboard sends no credential of its own. With auth closed it works through the Vite dev proxy's `HATCHERY_DASHBOARD_TOKEN`; a hosted/production dashboard would need its own token handling, which is not built. | The store's storage/retention guarantees
and the D28 transcript are in [`RETENTION.md`](RETENTION.md); key rotation,
retirement, backup/restore, their known gaps (KMS/escrow, multi-host, scheduled
rotation, secure erase, a signed manifest, Windows ACLs, the replay staging
file) and the D29 clean-copy transcript are in [`BACKUP.md`](BACKUP.md).

## Reproduction

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m pytest -q
python tests/fixtures/acceptance/tools/generate_fixtures.py --check
python scripts/verify_fixtures.py

# needs Node >= 20 and free ports 3002/5173
scripts/verify_setup.sh

# the store on its own (temporary root; no repository state is touched)
HATCHERY_SAMPLE_STORE=/tmp/hatchery-store python -m engine.cli store status --json

# the API's credentials and its audit chain, on their own (temporary database)
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/token.mjs create --role viewer --expires-in 1h
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/token.mjs list --json
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/audit.mjs verify   # exit 0, assurance keyed

# retention and an archive, on the same temporary database
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/audit.mjs status --max-rows 3
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/audit.mjs compact --max-rows 3 --apply
HATCHERY_DB_PATH=/tmp/hatchery-tokens.db node server/scripts/audit.mjs verify   # archive.join=proven
node server/scripts/audit.mjs verify --archive /tmp/audit-archives/audit-000001-000002.jsonl
```

Expected: `880 passed, 17 skipped, 3 xfailed`; the fixture scorecard
`13 passed, 0 failed, 3 known defects`; the setup check `32 passed, 0 failed`; the
server suite `97 passed, 0 failing`.

```bash
# Result bundles on their own (temporary root; no repository state is touched)
python -m engine.cli submit samples/eicar.com --no-sandbox -o /tmp/hb/run
python -m engine.cli results verify /tmp/hb/run --json            # ok: true, stage submit
python -m engine.cli results seal /tmp/hb/run --json              # idempotent, same hash
python -m engine.cli results seal /tmp/hb --all --json            # whole corpus, nested units first
python -m engine.cli results status --json --results /tmp/hb
python scripts/verify_manifest.py /tmp/hb/run --json              # the recipient's tool (D34)
python -m engine.cli results prune --older-than 0s --keep-last 1 --results /tmp/hb  # dry run
```

## Maintenance

1. Change fixture bytes in `tests/fixtures/acceptance/tools/generate_fixtures.py`,
   never by editing the generated files.
2. Regenerate files and `manifest.json` together.
3. Update an expectation only for an intentional behaviour change. When a
   recorded defect is fixed, remove its strict `xfail`, update the manifest and
   this document.

## Captured transcript (detector baseline, `4b48490`)

This is the previous clean-copy transcript, kept as the record of the detector
scorecard. The Phase 4a (D28) transcript — the one that includes the store
checks and the live `hatchery store` commands — is in
[`RETENTION.md`](RETENTION.md#captured-transcript).

```text
# Baseline verification transcript (clean checkout)

Captured: 2026-11-21T03:58:34Z (UTC)
Source: clean copy with no .venv, node_modules, data/, results/, uploads/ or caches

$ uname -srm; sw_vers
Darwin 27.2.0 arm64
ProductName:		macOS ProductVersion:		27.2.1 BuildVersion:		26B131 
$ python -V; node -v; npm -v
Python 3.12.14
v26.13.0
12.2.2
$ pip show yara-x pyelftools flare-capa 2>/dev/null | grep -E "^(Name|Version)"
Name: yara-x
Version: 1.24.0
Name: pyelftools
Version: 0.33
Name: flare-capa
Version: 10.0.0

$ python -m pytest -q
..                                                                       [100%]
702 passed, 17 skipped, 3 xfailed in 8.13s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
ok       tests/fixtures/acceptance/replay/one_packet.pcap
ok       tests/fixtures/acceptance/replay/empty.pcap
ok       tests/fixtures/acceptance/replay/malformed.pcap

$ python scripts/verify_fixtures.py
capa returned non-zero (10): ERROR capa: default embedded rules not found! (maybe you main.py:494 installed capa as a library?) ERROR capa: provide your own rule set via the `-r` option. main.py:495
HATCHERY fixture verification
manifest: tests/fixtures/acceptance/manifest.json (10 fixtures)
python:   3.12.14 (/tmp/hatchery-main-clean/.venv/bin/python)
capa:     CLI on PATH
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
detector/capa                PASS          unavailable (CLI) with preserved reason: capa exited with status 10: ERROR capa: default embedded rules not found! (maybe you main.py:494 installed cap
replay/strace-timestamp      PASS          9 events, tree {'1000': [1001]}, 1 connection
replay/strace-pid-first      PASS          9 events, tree {'1000': [1001]}
replay/file-events           PASS          {'total_events': 5, 'created_files': 1, 'modified_files': 1, 'deleted_files': 1}
replay/pcap-one-packet       PASS          1 packets, 1 connections
replay/pcap-empty            PASS          0 packets, 0 connections
replay/pcap-malformed        KNOWN-DEFECT  unreadable capture reported as an empty result (PCAP backend)

13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed

$ scripts/verify_setup.sh
HATCHERY baseline verification
repo:   /tmp/hatchery-main-clean
python: Python 3.12.14 (/tmp/hatchery-main-clean/.venv/bin/python3)
node:   v26.13.0 / npm 12.2.2
PASS  python/package-installed           0.1.0
PASS  ports/free                         API (3002) and dashboard (5173) are available
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  server/npm-ci                      dependencies installed from the lockfile
PASS  server/build                       production build succeeded
PASS  dashboard/npm-ci                   dependencies installed from the lockfile
PASS  dashboard/build                    production build succeeded
PASS  api/compiled-start                 node dist/index.js answered /api/health
PASS  api/enqueue                        task 51b7d5c2-498 queued (no subprocess held open)
PASS  api/restart-durability             task survived an API restart
PASS  worker/executes-job                worker drained the queue and exited 0
PASS  api/ingest-after-worker            completed task has the expected hash and static results
PASS  dashboard/dev-server               http://localhost:5173/ returned 200
PASS  dashboard/api-proxy                /api/health proxied to the API
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified

$ repository state after verification
no repository data directory (all state was temporary)
```
