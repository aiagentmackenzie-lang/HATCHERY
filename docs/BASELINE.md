# Baseline verification

Verified **27 November 2026**, D43 (admission control). This was a working-tree
baseline again: the numbers were measured before the `feat` commit, which changes no
runtime behaviour beyond the files it adds.
The D42 baseline was `bc4fa59` (a streamed upload is never written to a filesystem,
and the multipart path no longer deadlocks above ~128 KiB).
The D38 baseline was `b389c94` (PE/ELF structure in the bundle, schema 1.1) with
D36/D37 (ELF metadata, PCAP error path, rule calibration) and D35 (atomic key
publication) on `2d60c69`.
The D34 baseline was `2d60c69` (Phase 4f: nested-unit verification, corpus seal,
client verifier and the store-busy fix). The
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

## Current state (D42)

Measured in the checkout at `bc4fa59`, **not** from a fresh `git archive` copy: the
clean-copy protocol below was not repeated for this slice, so these numbers describe
a developer machine with a populated `.venv` and `node_modules`. What that changes:
nothing in the counts, and everything in the reproducibility claim — a clean copy is
the *stronger* form and is due again at the next slice that touches packaging.

```text
python -m pytest -q                    970 passed, 17 skipped
python -m ruff check .                 clean
python -m mypy engine/                 88 files, no issues
cd server && npm test                 111 passed, 0 failed
scripts/verify_setup.sh               42 PASS, 0 FAIL
fixture scorecard                     16 passed, 0 failed, 0 known defects (unchanged)
```

**And proven by CI, not by a local run.** D42 and D43 were pushed together as
`bc4fa59..b0fb6b2`; `HATCHERY CI` run **`46090131006`** is **9/9 green** on that head
(`python-gate` 3.12/3.13/3.14, `server-gate`, `queue-gate`, `hostile-inputs`,
`emulation-gate`, `detonation-gate`, `dashboard-gate`). The new gates ran rather than
being skipped: `server-gate` reports **111 tests / 111 pass / 0 fail** and names the
D42 and D43 cases (`ok 107 - an oversized multipart upload is 413 and queues nothing`,
`ok 108 - a multipart upload is stored through the engine, not written to a file`), and
its smoke test prints the live banner line
`Admission: 60 requests per 600s, 2147483648 bytes per 600s, 8 queued+running jobs`.
`queue-gate` runs the cross-language test that the owner column did not break the queue,
and `hostile-inputs` installs hypothesis and reports **63 passed** (the dependency step
fails the job if it is missing, so that is a real run).

CI's Python counts differ from this checkout in the honest direction: **966 passed, 21
skipped** on the runner against **970 / 17** here. The four extra skips are now named
rather than counted — run `46090753866` (same head plus `pytest -q -rs`) reports:

```text
SKIPPED tests/test_acceptance_fixtures.py:139, :149, :157   tshark not installed
SKIPPED tests/test_delivery_intake.py:595                  no real PDF on this host
```

Three are tshark-gated acceptance rows (independently reproduced by re-running here with
`/opt/homebrew/bin` off `PATH`, which adds exactly those three); the fourth is a sample
PDF the runner does not have. So four rows that assert something real do nothing on CI.
That was invisible before `-rs`, which is why the workflow now asks for the reasons: a
skip nobody can see is halfway to a green skip.

## What is verified (D38 clean copy, `b389c94`)

- A clean copy with no `.venv`, `node_modules`, `data/`, `results/`, `uploads/`
  or caches installs with `pip install -e ".[dev]"`, builds the server and
  dashboard, and passes the full Python suite: **893 passed, 17 skipped,
  0 xfailed** (was 880/17/3 at D35). D38 adds 4 real-submit tests for the binary
  sections: a PE run carries `static.pe` and `static.elf: null`, an ELF run the
  converse, a text run carries both keys as `null`, and `report.md` renders the
  structure the bundle carries. The three formerly pinned defects now pass
  (`test_benign_pe_has_no_unsupported_matches`, `test_elf_analyzer_parses_valid_elf`,
  `test_malformed_capture_is_reported`), and 8 tests were added: 5 pin atomic key
  publication (D35: the race loser uses the winner's key, an existing key is never
  overwritten and leaves no temporary, the final name is linked only after the bytes
  are complete and `0600`, a reader waits out an older create-then-fill writer, a
  permanently empty key file is a named `key-invalid`), 5 pin the ELF parser (D36: both
  pyelftools header forms, the unknown-value fallback, PIE from the normalised type,
  the real fixture, a non-ELF error), and 1 pins the calibration positive control
  (D37: an embedded `MZ`/`PK` header in a non-PE file still matches). `ruff` is clean
  and `mypy engine/` reports no issues in **86 source files**.
- **The server suite is 100 node tests, 0 failing** (was 84 at `511a978`; the
  three added by D38 pin that `static.pe`/`static.elf` reach `pe_json`/`elf_json`
  on ingest, that absent sections stay `null`, and that the schema declares both
  columns; 35 cover
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
- The fixture scorecard is **16 passed, 0 failed, 0 known defects**. It
  distinguishes a genuine match (EICAR), a completed scan with zero findings
  (negative text with rules loaded), a clean result from a valid minimal PE (D37),
  real ELF metadata (D36), an unreadable capture reported as an error with the
  tshark reason (D37), and a detector that could not run (capa unavailable, with
  its reason preserved).
- `scripts/verify_setup.sh` exercises the normal entry points against temporary
  state: **33 passed, 0 failed** (was 19/0 at D28; 21 at D29/D30; 24 at D31, which added
  `api/db-permissions`, `api/audit-chain-keyed` and `api/audit-key-announced`; 26 at D32,
  which added `api/audit-compaction` and `api/audit-archive-verified`; 29 at D33, which
  added `results/manifest-sealed`, `results/tamper-detected` and
  `results/prune-keeps-anchor`; D34 adds `results/seal-corpus` and
  `results/client-verifier`; D35 adds `store/first-key-race`; D38 adds
  `bundle/binary-metadata`).
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
  - **A binary's structure reaches the bundle and the report (D38).** A real
    `hatchery submit` of the PE fixture writes `static.pe` (machine, subsystem,
    sections, imports) with `static.elf: null`; the ELF fixture writes the converse
    (`arch`, `bits`, `elf_type`, `entry_point`, sections, security); a text sample
    carries both keys as `null`. The `report.md` written beside the bundle renders
    `### PE Structure` / `### ELF Structure` with those facts, and the API persists
    them to `pe_json`/`elf_json` (node tests).
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
| `tests/fixtures/acceptance/benign/benign_pe.exe` | valid PE32+ x64; **0 rule matches** with rules loaded (D37) |
| `tests/fixtures/acceptance/benign/hello.elf` | independently valid ELF64 x86-64 `ET_EXEC`; analyzer reports `x86-64 / 64-bit / EXEC (executable)` (D36) |
| `replay/trace_timestamp.log`, `trace_pid_first.log` | 9 events, process tree `1000 -> 1001`, 1 connection each |
| `replay/file_events.log` | 5 events: 1 created, 1 modified, 1 deleted |
| `replay/one_packet.pcap` | 1 packet, 1 connection (`tshark`) |
| `replay/empty.pcap` | 0 packets, no error |
| `replay/malformed.pcap` | unreadable: 0 packets **and** an error naming the tshark reason (D37) |

The manifest records the SHA-256 of each input; the generator reproduces them
byte-identically.

## Known defects on this baseline

**None.** The three defects recorded at D34 are closed:

| Defect (closed) | Fixed by | Now |
|---|---|---|
| Every PE matched `HATCHERY_Suspicious_HexStrings` on its own `MZ` header, and any PE with <=2 sections matched `HATCHERY_Packing_Generic_HighEntropy` | D37 | The hex-string rule ignores a file's own `MZ`/`PK` header; the packing rule measures the entropy its name promises. A benign minimal PE scores clean. |
| `ELFAnalyzer` raised `Unknown format code 'x' for object of type 'str'` on pyelftools 0.33 enums | D36 | Header enums are normalised for both pyelftools representations; valid ELF metadata is reported and `ET_DYN` is correctly recognised as PIE. |
| An unreadable capture yielded 0 packets and an empty `errors` list | D37 | A non-zero tshark exit is one named error, and analysis stops. |

The convention remains: a new recorded defect is pinned by a strict `xfail` in
`tests/test_acceptance_fixtures.py` and a `KNOWN-DEFECT` row in the scorecard, so
the baseline cannot drift silently.

## Not covered by this baseline

Docker detonation, the gVisor tier, Windows PE emulation, replay comparison,
LLM triage, MCP, STIX push, campaign clustering and the sample store's
key/retention semantics have their own suites and CI jobs. The API's credential
lifecycle, its CORS allow-list and the audit hash chain are covered by the server
suite and [`API-SECURITY.md`](API-SECURITY.md) (D30). This baseline is about
installation, packaging, normal entry points and static acceptance inputs; it
does not re-certify those features.

### Known gaps introduced or inherited by D38

| Gap | What it means |
|:--|:--|
| The dashboard has no ELF panel | It parses `pe_json` for the YARA view; `elf_json` is stored and returned by the API but nothing renders it. `version_info`, `resources` and full symbol lists are not rendered anywhere — the report shows counts and the first 20 sections. |
| No export mapping for binary structure | STIX, OCSF and Navigator still carry IOCs, ATT&CK and findings, not PE/ELF metadata. Adding it is an export-schema decision, not a producer one. |
| Older documents are silent, not upgraded | A schema-1.0 `analysis.json` has no `static.pe`/`static.elf`. Readers treat the absence as "not recorded" and render nothing; nothing backfills. That is honest, but a consumer cannot distinguish a pre-D38 run from a non-binary one without checking `schema_version`. |
| `is_valid_*` is a container fact | A parsed PE/ELF means the header and sections were readable, not that the binary is benign or that every field was understood. The analyzers are best-effort metadata, and their output is now more consequential (fingerprint, dashboard) rather than less. |
| The parsers are still not fuzzed | The PE/ELF parsers consume hostile bytes in-process. D38 publishes more of what they produce but adds no hostile-input harness; that is the P2 slice. |

### Known gaps introduced or inherited by D36/D37

| Gap | What it means |
|:--|:--|
| ELF metadata is not in the bundle | `ELFAnalyzer` is now correct and is used by the submit display and the fixture scorecard, but `analysis.json` still has no ELF section. A recipient of the run gets no ELF metadata. Wiring it in is a producer/schema change (D4), not part of this slice. |
| One ELF fixture, one shape | Only an ELF64 x86-64 `ET_EXEC` is exercised end to end. The enum shim is unit-tested for the integer and name forms, but no AArch64/RISC-V or `ET_DYN` fixture exists, and `entry_point`/sections are not cross-validated against an independent tool beyond the header check. |
| The entropy threshold is a judgement | `math.entropy(0, filesize) >= 7.2` has no packed corpus behind it. A small packed file whose headers dominate its entropy would not match; a high-entropy non-packed file would. The rule is `severity = "low"`; the packer detector remains the primary signal. |
| Errors, not a capture state | An empty-but-valid capture and an unreadable one are now distinguishable through `errors`, but the bundle summary carries no `capture_state`. Every consumer must read `errors`; a consumer that reads only `total_packets` still sees 0 for both. |
| The scapy fallback is untested here | This host has tshark, so the no-tshark path was not exercised. Its failures are recorded as errors, but a scapy parse of a hostile PCAP is not covered by the fixture suite. |

Known gaps introduced or inherited by D35

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

Expected: `893 passed, 17 skipped, 0 xfailed`; the fixture scorecard
`16 passed, 0 failed, 0 known defects`; the setup check `33 passed, 0 failed`; the
server suite `100 passed, 0 failing`.

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

## Captured transcript (D43, working tree on `361c58e`)

```text
$ python -m pytest -q
970 passed, 17 skipped            # unchanged; the only addition is an --owner assertion

$ python -m ruff check .          # clean
$ python -m mypy engine/          # 88 files, no issues

$ cd server && npm run typecheck && npm run build    # clean
$ cd server && npm test
111 passed, 0 failed              # was 106; +5 admission cases, one a real restart

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  api/admission-rate         second submission in the window is 429 with Retry-After
PASS  api/admission-audited      the refusal is in the chain as request.throttled, naming the limit
PASS  api/admission-owner        the queued job records its owner (anonymous)
RESULT: baseline verified
# 42 PASS, 0 FAIL (was 39)
```

The control, observed on a real server with the real engine (port 3003, `rate=1`):

```text
POST /api/submit #1 (multipart, tiny)      -> 200, sample stored, job queued with owner
POST /api/submit #2 (same window)          -> 429
   retry-after: 396                        (seconds to the window edge)
   x-hatchery-admission: rate 1/1
   {"error":"submission refused: too many submissions in this window",
    "reason":"admission-rate","limit":1,"used":1,"window_seconds":600,"retry_after":396}
audit_log (last row)                       -> 429 | request.throttled | rate 1/1 | anonymous
jobs.owner                                 -> anonymous
```

And the ordering, which is the point of the slice:

```text
HATCHERY_ADMIT_BYTES=1024, one 64 KiB multipart body
  -> 429 admission-bytes, limit 1024
  -> the stand-in engine was never invoked (invocation log unchanged)
  -> no tasks row, uploads/ unchanged
```

A real restart, not a second object in one process:

```text
server (rate=1) -> POST #1 -> 200
SIGKILL, start again, same database
                -> POST #2 -> 429 admission-rate   (the window survived)
```

### What is deliberately not in this baseline

A **sliding** window (a fixed window can pass ~2x the rate across a boundary), per-token
limits (every caller gets the same numbers), admission on token create/retire/expire or
the WebSocket, alerting or metrics beyond the audit row and the server log, and any
claim to stop a determined holder of a valid **admin** token — the claim is *bounded*,
not *safe*.

### Known gaps introduced or inherited by D43

| Gap | What it means |
|:--|:--|
| Fixed window | A caller can spend the whole rate at the end of one window and again at the start of the next, so a burst can pass roughly twice the limit. A sliding window needs a per-request ledger; a token bucket in SQLite is the cheaper fix and is its own slice. |
| Limits are global, not per credential | Every caller gets the same numbers. A stored token cannot be given its own budget, and an operator with a noisy integration cannot raise it for one caller without raising it for all. |
| The byte quota reserves the upload limit | A submission reserves 256 MiB and settles to the real size, so concurrent submissions can refuse each other earlier than the true byte total requires. That is deliberate — the alternative is charging after the write — but it makes the limit tighter than it reads under concurrency. |
| The job cap depends on `jobs.owner` | A job queued by a build before D43 has a NULL owner and is invisible to every caller's count. It still occupies a worker; it just does not count against anyone. |
| An unreadable queue skips the job cap | `countActiveJobs` returns `null` and the cap is not applied, because a missing queue file on a fresh install is "no jobs". A corrupt queue therefore loses the job cap (and the log says nothing) rather than blocking every submission. |
| `Retry-After` for jobs is a guess | 30 s, because the API cannot know when a worker will finish. A client that honours it exactly may be refused again. |
| Counters are not tamper-evident | `admission_counters` is ordinary API state, covered by the database's `0600` posture, not by the audit chain. Deleting a row resets a budget; the audit rows that recorded the refusals would still show the pressure. |
| Only submissions are controlled | Token create/retire/expire, the WebSocket and every read are not admission-controlled. A read does not fill a disk or a queue, but it is not free either, and it is unbounded. |

## Captured transcript (D42, `bc4fa59`)

```text
$ python -m pytest -q
970 passed, 17 skipped            # was 963/17; +7 stream-intake cases

$ python -m ruff check .          # clean
$ python -m mypy engine/          # 88 files, no issues

$ cd server && npm run typecheck && npm run build    # clean
$ cd server && npm test
106 passed, 0 failed              # was 105; +1 (a real multipart upload, against a stub engine)

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  api/multipart-upload              streamed into the encrypted store; uploads/ left empty
PASS  api/multipart-large               2 MiB streamed in 0s (128 KiB used to deadlock); no file staged
PASS  api/oversized-filepath            300 MiB filePath refused with 413 before enqueue; no residue
PASS  intake/stdin-limit                300 MiB on a pipe refused while reading; nothing stored
PASS  worker/store-backed-job           job records a content address and completed from it
RESULT: baseline verified
# 39 PASS, 0 FAIL (was 37)
```

The upload boundary, measured against the compiled server with a real `curl` and a
real store. The left column is the defect; the right is this revision.

```text
                        BEFORE (4276042)                  AFTER (bc4fa59)
64 KiB multipart        200 in 149 ms                     200
96 KiB multipart        200                              200
128 KiB multipart       no response (5 s cap)            200
1 MiB multipart         no response (6 s cap)            200
2 MiB multipart         no response                     200 in <1 s
40 MiB multipart        HTTP 100, then nothing (20 s)     200 in 326 ms
uploads/ after upload   <taskId>/<name>, plaintext        empty (nothing is written)
blob on disk            41,943,101 B (ciphertext)         41,943,101 B (ciphertext)
task row file_path      uploads/<taskId>/big.bin          store:<sha256>
worker                  reads the staged file             reads the store; exit 0 in 4.5 s
bundle sample name      big.bin                           big.bin (the client's name, not the marker)
```

A `store put --stdin` at 300 MiB is refused as `too-large` with **no new blob**
(before/after `.sample` count unchanged): the reader stops at 256 MiB + one chunk
instead of draining the pipe.

### What is deliberately not in this baseline

Streaming **ciphertext**: the v1 envelope authenticates the plaintext length in its
AAD, so the writer must know the size before writing the header, and a stream does
not. The bytes are encrypted from memory, bounded by the same 256 MiB cap — a
segmented v2 envelope is the fix and is its own migration. Also absent: a per-token
quota, rate limit or concurrency cap (D43) — an accepted upload can still fill the
disk, and a stored-then-abandoned upload is reclaimed only by `store prune`; a
cancellation API; and any change to the JSON `filePath` branch, which reads an
operator's own file and is bounded by D40.

### Known gaps introduced or inherited by D42

| Gap | What it means |
|:--|:--|
| The sample is held in memory, not streamed to ciphertext | At the 256 MiB cap a stored upload costs ~256 MiB of RSS in the engine (and again to string-scan). The cap makes it constant, not small. The v1 header is why: the length is in the authenticated AAD, so a writer must know it up front. |
| A stored-then-abandoned upload is an orphan blob | If the client disconnects after the store call but before the enqueue, a complete encrypted blob has no job. `store prune` reclaims it; nothing else will, because there is no cancellation API. It is never a job pointing at nothing, which is the property that matters. |
| No admission control | A token can still fill the disk with accepted 256 MiB samples, and a stalled body pins a Python process until the route's 300 s cap. D43 is the slice. |
| The engine's limit is applied while reading, not before it | A pipe has no `lstat`. The API keeps its own earlier refusal (`limits.fileSize`), so a caller learns at the boundary, but bytes already on the wire cannot be un-sent. This is the one guarantee a file gets and a stream cannot. |
| `uploads/` is still an allowed `filePath` root | Nothing writes to it any more, but an operator who keeps samples there deliberately can still submit by path. The API itself never creates a file in it. |
| The server suite now depends on a stub engine | `server/test/fixtures/fake-engine.mjs` implements only the store/queue contract, because `server-gate` has no Python. The real path is covered by `verify_setup.sh` and the engine's suite; a divergence between the stub and the engine would be caught there, not here. |

## Captured transcript (D41, `ccb2955`)

Server-only slice: no Python module changed, so the Python numbers are the D40
baseline and are restated here so the pair can be read together.

```text
$ python -m pytest -q
963 passed, 17 skipped            # unchanged by D41

$ cd server && npm run typecheck && npm run build    # clean
$ cd server && npm test
105 passed, 0 failed              # was 100; +5 upload-limit cases

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  api/enqueue                        task ... queued (no subprocess held open)
PASS  api/multipart-upload               small upload queued and stored under the temp uploads root
PASS  api/oversized-filepath             300 MiB filePath refused with 413 before enqueue; no residue
PASS  api/ingest-after-worker            completed task has the expected hash and static results
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified
# 37 PASS, 0 FAIL
```

The upload boundary, observed rather than asserted:

```text
POST /api/submit (multipart, 8 KiB body, plugin limit lowered to 1 KiB)
  -> 413 {"statusCode":413,"error":"Payload Too Large","message":"request file too large"}
  -> uploads/ unchanged (no partial file, no task directory)

POST /api/submit (multipart, two file parts, files: 1)
  -> 413 "reach files limit", uploads/ unchanged

POST /api/submit {"filePath": "<300 MiB sparse>"}
  -> 413 {"error":"sample too large","limit":268435456,"size":314572800}
  -> no tasks row, no uploads/<task>/ directory

MAX_UPLOAD_BYTES (server) == DEFAULT_MAX_SAMPLE_BYTES (engine/store/store.py) == 268435456
```

### What is deliberately not in this baseline

No per-account quota or rate limit, no streaming of the upload into the encrypted
sample store (the route still writes a plaintext file that the worker later
stores), and `HATCHERY_UPLOADS_DIR` is a test seam before it is an operator knob.
**The plaintext staging was removed by D42 (see above); the quota is still absent
and is D43.**
The `app.inject` refusal test was replaced with a real listener after it hung:
"the gate hangs" is a failure mode a gate must not have.

## Captured transcript (D40, `6603de4`)

Same clean-copy procedure as the D39 transcript. The intake numbers are measured
on this machine with `/usr/bin/time -l` (peak RSS) on the *same* 400 MiB file
before and after the change.

```text
$ python -m pytest -q
963 passed, 17 skipped in 44.70s
# 980 collected; +7 over D39 (956/17)

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
# fixture manifest regenerated byte-identically
$ python scripts/verify_fixtures.py
16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  python/package-installed           0.2.0
PASS  hostile/named-not-crash            3 containers: named, bounded, sealed, no traceback
PASS  intake/oversized-before-read       64 GiB refused in 1s from the stat; no bundle, no traceback
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified
# 35 PASS, 0 FAIL

$ ruff check engine/ tests/ scripts/   # All checks passed!
$ mypy engine/                         # Success: no issues found in 88 source files
$ (cd server && npm test)              # tests 100, pass 100, fail 0
$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
# tests 3, pass 3, fail 0
$ (cd dashboard && npm run build)      # built, exit 0
```

The intake cost, before → after, measured with `submit --no-sandbox` on the same
files:

```text
400 MiB regular file   474,464,256 B peak RSS / 0.27 s  ->  55,050,240 B / 0.13 s
64 GiB sparse file     (allocate 64 GiB, then refuse)   ->  55,017,472 B / 0.12 s
```

Both refusals are one line naming `too-large` and the limit, exit 1, no bundle.

### What is deliberately not in this baseline

Streaming encryption/scanning (a sample *at* the 256 MiB limit still costs
~256 MiB to store and again to string-scan; the cap makes it a constant, not a
function of the file), a configurable limit, and the API's multipart route. **The
route was closed by D41 (one limit, clean refusal) and D42 (no plaintext file at
all, and the >128 KiB deadlock fixed); this paragraph is the state at D40.**

## Captured transcript (D39, `09de636`)

Same clean-copy procedure as the D38 transcript: no `.venv`, `node_modules`,
`data/`, `results/`, `uploads/` or caches, produced from the code commit with
`git archive`. The hostile rows are also a CI job of their own
(`hostile-inputs`), which fails if `hypothesis` is missing so the property
module cannot degrade into a green skip.

```text
$ python -m pytest -q
956 passed, 17 skipped in 43.78s
# 973 collected; +63 over the D38 clean copy (893/17)

$ pytest tests/test_hostile_inputs.py tests/test_stage_isolation.py \
         tests/test_parser_properties.py -q
63 passed
# 38 hostile-input rows (29 fixtures + 6 CLI + determinism + documents),
# 13 stage-isolation rows, 12 parser properties

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
# fixture manifest regenerated byte-identically

$ python scripts/verify_fixtures.py
16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  python/package-installed           0.2.0
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  bundle/binary-metadata             PE structure in static.pe, rendered in report.md
PASS  hostile/named-not-crash            3 containers: named, bounded, sealed, no traceback
PASS  store/first-key-race               4 concurrent first submits: one complete key, no partial read
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified
# 34 PASS, 0 FAIL

$ ruff check engine/ tests/ scripts/   # All checks passed!
$ mypy engine/                         # Success: no issues found in 87 source files
$ (cd server && npm test)              # tests 100, pass 100, fail 0
$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
# tests 3, pass 3, fail 0
$ (cd dashboard && npm run build)      # built, exit 0
```

The hostile contract was checked through the installed CLI, not only in unit
tests. Three corpus containers, each a real `submit --no-sandbox`:

```text
ole_truncated        exit 0  bundle+manifest sealed
                     static.delivery.errors: "ole_truncated: OLE/CFB parse failed: no FAT sectors found"
zip_ratio_bomb       exit 0  bundle+manifest sealed
                     static.delivery.flags: ["zip-suspicious-ratio"]
                     static.delivery.unsupported[0]: "compression ratio 1028:1 exceeds the zip-bomb guard"
gzip_corrupt_deflate exit 0  bundle+manifest sealed
                     static.delivery.errors: "gzip decompression failed: Error -3 while decompressing data"
no "Traceback" on stdout or stderr for any of the three
```

And the funnel itself, forced (not observed): a monkeypatched `PEAnalyzer`,
`ELFAnalyzer`, `StringExtractor`, `PackerDetector`, `CapaScanner`,
`YARAScanner`, `extract_delivery`, `PackerDetector` (both the top-level stage and
inside an extracted child) and `StraceParser` each raise once; the run still writes `bundle/analysis.json`,
still writes `manifest.json`, `verify_run` reports `ok: true`, `bundle.errors`
names the stage and the exception, and a defect in the bundle writer exits 6
with one line.

### What is deliberately not in this baseline

No mutational fuzzer (no AFL/libFuzzer, no long-running corpus), no in-process
memory ceiling (the caps are documented and tested; a 64 MiB gzip bomb is still
decompressed to the cap before it is refused), no fuzzing of YARA-X, pefile or
pyelftools themselves, and no top-level sample-size cap (`read_bytes()` in the
string extractor and uploader still loads the whole sample; the *extraction*
path is bounded). The gVisor/strace CLI wiring is unit-tested through
`_parse_syscall_log`; the sandbox-side end-to-end row stays behind
`HATCHERY_E2E=1`.

## Captured transcript (D38, `b389c94`)

Clean copy with no `.venv`, `node_modules`, `data/`, `results/`, `uploads/` or
caches, produced from the code commit with `git archive`.

```text
$ python -m pytest -q
893 passed, 17 skipped in 38.27s

$ python scripts/verify_fixtures.py
16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  python/package-installed           0.1.0
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  bundle/binary-metadata             PE structure in static.pe, rendered in report.md
PASS  store/first-key-race               4 concurrent first submits: one complete key, no partial read
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified
# 33 PASS, 0 FAIL

$ ruff check engine/ tests/ scripts/   # All checks passed!
$ mypy engine/                          # Success: no issues found in 86 source files
$ (cd server && npm ci && npm run typecheck && npm run build && npm test)
# tests 100, pass 100, fail 0
$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
# tests 3, pass 3, fail 0
$ (cd dashboard && npm ci && npm run build)   # built, exit 0
```

The binary section was checked on a real run, not only in unit tests:

```text
static.pe: {is_valid_pe: true, machine_type: "x64 (AMD64)", subsystem: "Windows CUI (Console)",
            is_64bit: true, sections: [{name: ".text", raw_size: 512}], imports: []}
static.elf: null
report.md: "### PE Structure" / "- **Machine:** x64 (AMD64), 64-bit" / "`.text` (512 B)"

static.elf: {is_valid_elf: true, arch: "x86-64", bits: 64, elf_type: "EXEC (executable)",
             entry_point: 4198400, sections: 3, security: {is_pie: false, is_stripped: true}}
static.pe: null
report.md: "### ELF Structure" / "- **Architecture:** x86-64, 64-bit, Little-endian"
```

## Captured transcript (Phase 4g, `cd70b55`)

Clean copy with no `.venv`, `node_modules`, `data/`, `results/`, `uploads/` or
caches, produced from the code commit with `git archive` and run on the host
described above.

```text
$ uname -srm; sw_vers | head -3; node -v; npm -v
Darwin 27.2.0 arm64
ProductName:            macOS
ProductVersion:         27.2.1
BuildVersion:           26B131
v26.13.0
12.2.2
$ pip show yara-x pyelftools flare-capa | grep -E "^(Name|Version)"
Name: yara-x
Version: 1.24.0
Name: pyelftools
Version: 0.33
Name: flare-capa
Version: 10.0.0

$ python -m pytest -q
889 passed, 17 skipped in 37.67s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
ok       tests/fixtures/acceptance/replay/one_packet.pcap
ok       tests/fixtures/acceptance/replay/empty.pcap
ok       tests/fixtures/acceptance/replay/malformed.pcap

$ python scripts/verify_fixtures.py
fixture/hashes               PASS          10 files match the manifest
static/eicar                 PASS          HATCHERY_EICAR_TestFile; 5 rule files loaded
static/negative-control      PASS          0 matches with 5 rule files loaded
static/benign-pe-structure   PASS          PE32+ x64 (AMD64); Windows CUI (Console)
static/benign-pe-yara        PASS          0 matches with 5 rule files loaded
static/benign-elf-fixture    PASS          independently parsed: EM_X86_64 ET_EXEC
static/benign-elf-analyzer   PASS          x86-64, 64-bit, EXEC (executable), 3 sections
static/packer-pe             PASS          no packer indicators, no error
static/packer-elf            PASS          inapplicable with an explicit error: Failed to parse PE: 'DOS Header magic not found.'
detector/capa                PASS          unavailable (Python) with preserved reason: capa Python API not usable: module 'capa' has no attribute 'main'
replay/strace-timestamp      PASS          9 events, tree {'1000': [1001]}, 1 connection
replay/strace-pid-first      PASS          9 events, tree {'1000': [1001]}
replay/file-events           PASS          {'total_events': 5, 'created_files': 1, 'modified_files': 1, 'deleted_files': 1}
replay/pcap-one-packet       PASS          1 packets, 1 connections
replay/pcap-empty            PASS          0 packets, 0 connections
replay/pcap-malformed        PASS          unreadable capture reported: PCAP could not be read: tshark: The file "..." isn't a capture file in a format TShark understands.

16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed

$ PYTHON=$PWD/.venv/bin/python scripts/verify_setup.sh
PASS  python/package-installed           0.1.0
PASS  ports/free                         API (3002) and dashboard (5173) are available
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  16 passed, 0 failed, 0 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  store/encrypted-at-rest            content-addressed AES-256-GCM blob, 0600, no plaintext
PASS  store/first-key-race               4 concurrent first submits: one complete key, no partial read
...
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged
RESULT: baseline verified
# 32 PASS, 0 FAIL

$ ruff check engine/ tests/ scripts/
All checks passed!
$ mypy engine/
Success: no issues found in 86 source files

$ (cd server && npm ci && npm run typecheck && npm run build && npm test)
# tests 97, pass 97, fail 0
$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
# pass 3, fail 0
$ (cd dashboard && npm ci && npm run build)
# built in 514ms
```

The clean copy contained no `data/`, `results/` or `uploads/` after every gate.

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
