# Audit-log retention, segmented chains and the disk-growth guard (D32)

This is the operator's guide to Phase 4d: how the audit log stays **finite without
being rewritten**, what a compaction writes, how to verify across the boundary (and
offline), what happens when the disk is full, and exactly what was not verified. The
decision record is [`DECISIONS.md`](DECISIONS.md) **D32**; D25 governs the log's
contents, D30 its chain, D31 its keying and anchor. The clean-copy transcript is at the
end of this page.

The problem this page answers is not "how do I delete old rows". A hash chain cannot
survive a `DELETE` in the middle: the next row's `prev_hash` points into the deleted
region, so either verification breaks or someone "fixes" it by rewriting hashes — which
is the forgery the chain exists to detect. `audit_log` therefore grew for the life of
the deployment. D32 makes it finite by **archiving a segment and handing the chain off**,
and by keeping every claim the verifier makes true across that boundary.

## The rules, in one place

| Rule | Detail |
|:--|:--|
| The server never deletes an audit row | no timer, no scheduled task, no request path. Only `npm run audit -- compact --apply` removes a row, and it is a host-local operator action |
| Retention is off by default | with no rule configured, `status` says `policy: OFF` and `compact` refuses with a usage error instead of guessing |
| A compaction always leaves a live anchor row | `--keep-rows` (default 1); `--max-rows 0` is clamped and the clamp is reported |
| Nothing is ever re-hashed | the live rows keep their `entry_hash`/`entry_mac`; the archived rows keep exactly the ones they were written with |
| The join is provable | the first live chained row's `prev_hash` equals the archived tail's `entry_hash` |
| A crash is resumable | archive first, manifest last, then the delete — each step re-uses what a previous run left behind |
| A missing/tampered/non-linking archive is a break | its own classification, never `ok` |
| Growth is visible, never pruned | warning thresholds in `audit status`, the verify response and the startup banner |
| No secret is in an archive | it is a projection of `audit_log`, which never held a token, header, body or sample byte; the manifest holds key **ids** only |
| Archives are operator state | created `0600` in a `0700` directory, git-ignored, never printed with key material |

## The policy

| Knob | Meaning | Default |
|:--|:--|:--|
| `--older-than 30d` · `HATCHERY_AUDIT_RETENTION_DAYS` | archive rows created more than this long ago (`s`/`m`/`h`/`d`/`w` or seconds) | unset |
| `--max-rows N` · `HATCHERY_AUDIT_RETENTION_MAX_ROWS` | archive everything beyond the newest N chained rows | unset |
| `--keep-rows N` · `HATCHERY_AUDIT_KEEP_ROWS` | always keep the newest N chained rows live — the anchor | `1` |
| `--max-segment-rows N` · `HATCHERY_AUDIT_MAX_SEGMENT_ROWS` | at most N rows archived per run | `50000` |
| `--apply` | actually archive and delete | dry run |
| `--gzip` · `--out DIR` | compress with Node's `zlib` · write elsewhere | off · `<db dir>/audit-archives` |

When both a time rule and a count rule are given, the **intersection** applies: a row
moves only if it is both older than the age and beyond the count. That is the
conservative reading and it never archives recent activity because one rule was loose.

`--max-rows N` keeps N live rows **including the `audit.compacted` record the run
appends**, so repeated runs settle instead of archiving one row and adding one back for
ever.

**Pre-chain rows are never archived.** Rows written before D30 have no `entry_hash`, so
they cannot be verified and the `legacy_row_count` anchor that makes their deletion
visible would have to move. `status` reports them as `pre-chain`; they are a small,
one-time set by construction.

## Commands

```bash
cd server

# What is there, how big it is, what a run would move, and whether growth is over budget.
npm run audit -- status
npm run audit -- status --older-than 30d
npm run audit -- status --max-rows 100000 --json

# A dry run is the default: nothing is written, nothing is deleted.
npm run audit -- compact --max-rows 100000
# Apply it. Exactly the window the dry run reported is archived and deleted.
npm run audit -- compact --max-rows 100000 --apply
# Gzip the archive and keep it outside the data directory.
npm run audit -- compact --older-than 90d --gzip --out /var/backups/hatchery-audit --apply

# Verify the live chain *and* every archive behind it.
npm run audit -- verify
npm run audit -- verify --no-archive          # presence only; says it did not read them
npm run audit -- verify --expect-head 412:<hash>
npm run audit -- verify --archive /var/backups/hatchery-audit/audit-000001-000021.jsonl \
  --keyring /etc/hatchery/.audit-keyring      # offline: no database needed

npm run audit -- archives                     # every recorded segment
npm run audit -- head                         # live head + archived counts, to record elsewhere
npm run audit -- key status | key rotate      # ids only, never material
```

Every command accepts `--json` (one object on stdout) and `--db PATH` (default
`$HATCHERY_DB_PATH` or `data/hatchery.db`). Exit codes: **0** success and verification
passed, **1** verification failed or the operation failed, **2** usage error — including
`compact` with no policy, because retention is off by default.

## What a compaction writes

Given a window `first_id … last_id`:

1. **The archive** — `audit-000001-000021.jsonl` (or `.jsonl.gz`), one JSON object per
   line, containing exactly the columns `audit_log` stores: `id`, `actor`, `role`,
   `authenticated`, `method`, `path`, `status_code`, `action`, `detail`, `created_at`,
   `prev_hash`, `entry_hash`, `key_id`, `entry_mac`. Fixed key order, so the same rows
   always produce the same bytes. `0600`, written temp → `fsync` → rename → directory
   `fsync`.
2. **The manifest** — `audit-000001-000021.manifest.json`, written **last**, same atomic
   sequence. It records `format`/`manifest_version`/`created_at`, the archive's path,
   SHA-256 and size (and whether it is gzipped), the window and the policy that selected
   it, the first and last row's `entry_hash`/`entry_mac`/`key_id`, the key ids present,
   the chain algorithm and genesis constant, and the live head at compaction time.
   **Nothing in it is a secret** — key ids, not material.
3. **The handoff** — in one `BEGIN IMMEDIATE` transaction: re-read and re-check the
   window; append `action: "audit.compacted"` naming the archive path, the manifest
   SHA-256 and the archived tail; delete exactly the archived rows (asserting the count);
   record `archive_segments`, `archived_row_total`, `archive_last_*`,
   `chained_row_count` and `last_compacted_at` in `audit_chain_meta`.

The invariant, in one sentence: **the first live chained row's `prev_hash` is the archived
tail's `entry_hash`.** It holds whether that row is a surviving live row or the
`audit.compacted` record, so an offline verifier holding the archive can prove the join
with two hashes.

The live chain never restarts and never forks. The archived rows keep their original
digests and MACs, and `chained_rows_total` (maintained by the appender) proves that
everything that ever existed is either live or archived:

```
chained_rows_total == live chained rows + archived_row_total
```

A row in neither was deleted outside a compaction — a `deleted` break.

## Crash-resume, step by step

The archive and the manifest are deterministic and are **adopted, not rewritten** when a
re-run produces the same window.

| Interrupted | On disk | A second `compact` |
|:--|:--|:--|
| during the archive write | a `.tmp-` file only | ignores it, writes the archive, continues |
| after the archive rename, before the manifest | archive, no manifest, rows intact | re-derives the same bytes, reuses the archive, writes the manifest, continues |
| after the manifest, before the transaction | archive + manifest, rows intact | adopts the manifest (same SHA-256), completes the delete |
| inside the transaction | rolled back — rows intact, no `audit.compacted` row | re-runs the transaction |

A file with the expected name but different content is **refused**, not overwritten; so is
an existing manifest that does not describe the archive. The tests interrupt a real
compaction at each of those three steps and then assert that the union of live ids and
archived ids is exactly the set that existed before, and that exactly one archive and one
manifest exist.

## Compaction while the API is running

- **File I/O happens outside the write lock.** The archive and the manifest are written
  first; the transaction that re-checks the window, appends the `audit.compacted` record
  and deletes the rows is a handful of statements.
- **The write lock serialises.** `BEGIN IMMEDIATE` is taken before the window is
  re-checked, with a 5 s busy timeout and five bounded retries. A concurrent append
  cannot be lost. A concurrent compaction either wins or observes the rows already gone
  and aborts with `another compaction or a deletion got there first` — having deleted
  nothing, and saying so.
- Measured: 30 concurrent `GET /api/tasks` against the built server during a real
  `compact --apply`. Every request answered 200; `chained_rows_total` grew by exactly 31
  (30 request rows + the `audit.compacted` row); the archives and the live chain spliced;
  the log verified.

## Verifying across the boundary

`verify` reports the segments in addition to the D30/D31 fields:

```json
{
  "ok": true,
  "assurance": "keyed",
  "coverage": {"chained_rows": 20, "mac_rows": 20, "unkeyed_rows": 0, "legacy_rows": 0},
  "segments": {"live_rows": 20, "archived_rows": 21, "archived_segments": 1,
               "live_first_prev_hash": "5641e3a7…", "archived_tail_hash": "5641e3a7…",
               "join": "proven"},
  "archive": {"recorded": true, "present": true, "checked": true, "verified": true,
              "mode": "full", "segments": 1, "rows": 21,
              "manifest_sha256": "8f3f7385…", "archive_sha256": "4c39f5a4…",
              "tail": {"id": 21, "entry_hash": "…", "entry_mac": "…", "key_id": "…"},
              "join": "proven", "missing": [], "error": null, "reason": null},
  "archive_verified": true,
  "growth": {"rows": 20, "bytes": 217408, "warn_rows": 500000,
             "warn_bytes": 268435456, "over": false, "enforced": false,
             "reasons": [], "message": "audit log is below its warning threshold"},
  "append_failures_since_start": 0,
  "append_failures_total": 0,
  "append_failures_persisted": true
}
```

### Read `assurance` and `archive_verified` together

`assurance` (`empty`/`unkeyed`/`mixed`/`keyed`) still describes **the live rows** and does
not change because history moved to an archive. That is deliberate: a compaction must not
silently weaken the claim. Whether the archived rows were checked is a separate field,
and a verifier that did not read them says so:

| `archive.checked` | `archive_verified` | What it means |
|:--|:--|:--|
| `true` | `true` | every archived row's digest and MAC was recomputed, the manifest hash and the file hash were checked, and the join was proven |
| `true` | `false` | the archives were read and something is wrong — see `first_broken` |
| `false` | `false` | the archives were only stat-ed (`--no-archive`), or verification stopped at a break before reading them, or this was a resumed page |

`?archive=presence` (HTTP) and `--no-archive` (CLI) stat the files, report the recorded
manifest hash and check the join from the metadata, and set `archive.checked: false`.
They are for a fast check, not for evidence.

### Each archive failure has its own classification

| Classification | What happened |
|:--|:--|
| `archive-missing` | a recorded archive file or manifest is gone — history was removed, not archived |
| `archive-mismatch` | the file is not the one the manifest recorded, and every row still verifies internally |
| `archive-modified` | an archived row's digest or MAC does not verify — reported **at that row**, with the manifest-hash mismatch named |
| `archive-truncated` | archived rows are missing from the middle or the end, or the tail moved |
| `archive-invalid` | the archive, the manifest or the segment metadata cannot be parsed |
| `join-mismatch` | the live chain's first `prev_hash` is not the archived tail |

A deleted archive is a break and the CLI exits 1. It is **not** reported as a shorter,
green history.

### Anchors across a compaction

`verify --expect-head <id>:<hash>` means "the head I recorded is still part of this log".
The anchored row is located in the live chain **or** in a verified archive, and the
response says where (`anchor.found_in`) and whether it is still the newest row
(`anchor.head_at_anchor`). An anchor that is present nowhere is `replaced` and fails. An
anchor that lives in an archive you did **not** read is `matches: null` and the CLI exits
non-zero — "unconfirmed" is not a pass.

This corrected D31, which compared the anchored head to the current head for equality:
that made an anchor unusable after a single append (let alone a compaction) and could not
tell "more rows were written" from "the tail was truncated and the head rewritten".

### Offline verification

An archive is evidence an operator can carry to another machine:

```bash
npm run audit -- verify --archive audit-000001-000021.jsonl --keyring .audit-keyring
```

It reads the archive and its manifest, checks the manifest's SHA-256 of the archive, the
row count, the first/last id, every `prev_hash`/`entry_hash`, every `entry_mac` against
the key ring, and the tail against the manifest's recorded tail. It prints the tail hash
and the archive's first `prev_hash`, which is what you splice onto the next chain:

- the first segment's first `prev_hash` is the genesis constant (`000…0`);
- a later segment's first `prev_hash` is the previous segment's tail;
- the live chain's first `prev_hash` is the last segment's tail.

Without a key the answer is `unknown-key` (`supply the ring that authenticated this
archive`), never a pass. The key ring is supplied with `--keyring PATH` or
`--key-file PATH`; otherwise `HATCHERY_AUDIT_KEY`/`_FILE` is used, then a ring beside the
archive (then one directory up, then the working directory) — a default installation
keeps the ring beside the database and the archives in `<db dir>/audit-archives/`.

**What an archive proves:** every row in it existed with exactly those fields and MACs,
the file is the one the manifest recorded, and the chain continues into the live segment.
**What it does not prove:** that no row was *never written* (an append that failed), that
the archive has not been replaced wholesale together with its manifest, or anything about
rows the operator later deletes from the archive directory by hand.

## The disk-growth guard

| Variable | Default | Meaning |
|:--|:--|:--|
| `HATCHERY_AUDIT_WARN_ROWS` | `500000` | warn at this many audit rows (`0` disables) |
| `HATCHERY_AUDIT_WARN_BYTES` | `268435456` (256 MiB) | warn at this database size, database + WAL (`0` disables) |

Reported by `npm run audit -- status` (row count, oldest and newest id and date, database
size, archive state, what a run would remove), by every verify response (`growth`), and by
the **startup banner**:

```
[hatchery] AUDIT LOG GROWTH WARNING — 600000 audit rows (warning at 500000). Nothing was
deleted: run `npm run audit -- status` and then `npm run audit -- compact --apply`
(retention is an operator decision).
```

`growth.enforced` is always `false`, in the response and in the code: the guard makes
growth visible and never deletes. An API that prunes its own evidence is a worse defect
than a big log.

### When the disk is actually full

| Path | What happens |
|:--|:--|
| The request | unaffected. The audit append runs in `onResponse`, after the reply is sent; the request already has its 200. **D25 is intact — auditing never turns a completed request into a 500.** |
| The audit row | lost. `recordAudit` logs one line with the reason (no credential), increments the counter, and returns. The chain cannot see a row that was never written. |
| The counter | `append_failures_since_start` for this process; `append_failures_total` persisted in `audit_chain_meta` (best effort). If the failure is a completely unwritable database, the write that records the failure fails too and `append_failures_persisted` is `false` — the server log is then the only record, and the report says so. |
| Compaction | refuses. The archive or manifest write throws and **no row is deleted**; the error names the path. |
| Verification | still works (it only reads), and the non-zero failure count is in its response. |

So what is lost when the disk is full is **one audit row per failed append** — visible in
the server log and in the counter, never silently dropped, and never traded for space.

## Operator checklist

- [ ] Watch the startup banner and `npm run audit -- status`. Growth over a threshold is
      a warning, not an action — nobody is going to compact anything for you.
- [ ] Choose a policy deliberately: `--older-than` matches a retention obligation;
      `--max-rows` matches a disk budget. Running both applies the stricter intersection.
- [ ] Always run `compact` **without** `--apply` first and read the window it prints.
      `--apply` deletes exactly that window.
- [ ] Keep `--max-segment-rows` at its default unless you have measured the verification
      cost. It bounds the archive, the lock and `verify`.
- [ ] Never edit an archive or a manifest. An edited archive is `archive-modified` and a
      rewritten one is `archive-mismatch`; the evidence is worth more than the tidiness.
- [ ] Treat `<db dir>/audit-archives/` as evidence: `0600`, backed up, **not** committed
      (`.gitignore` covers it), and not on a share you do not control.
- [ ] Copy the archive off the host before you expire it. Nothing in HATCHERY deletes or
      ships an archive; that lifecycle is yours.
- [ ] Keep the audit key ring with the archives (or supply it at verification time).
      An archive whose key is gone is `unknown-key`, not "fine".
- [ ] Run `npm run audit -- verify` after a compaction, then
      `npm run audit -- verify --archive <file> --keyring <ring>` on a machine that does
      not have the database — that is the claim an archive is supposed to support.
- [ ] Re-record the head after a compaction (`npm run audit -- head`). Old anchors still
      verify, but the newest head is the one that catches a later truncation.
- [ ] Do not schedule a compaction you have not watched once. It is an operator decision
      by design, not a cron someone forgot about.

## Captured transcript

Clean copy of the repository at the code+tests commit `c82ad5e` (on top of `a70c421`),
with no `.venv`, `node_modules`, `data/`, `results/`, `uploads/` or caches. The literal
protocol uses `python3.12`; the interpreter uv had already installed (`cpython-3.12.14`)
was used directly and `python -V` in the transcript confirms 3.12.14. A uv venv ships no
`pip`, so `python -m ensurepip --upgrade` was run before `pip install -e ".[dev]"`.
`scripts/verify_setup.sh` needs the interpreter's absolute path because it changes
directory internally. The documentation commit that follows does not change the code
under test.

```text
# HATCHERY Phase 4d — clean-copy verification transcript

Captured: 2026-11-21T13:17:03Z
Source:   git archive c82ad5e (D32 code and tests), unpacked into
          /tmp/hatchery-phase4d-clean; no .venv, node_modules, data/, results/,
          uploads/ or caches in the archive.

$ uname -srm; sw_vers -productVersion
Darwin 27.2.0 arm64
27.2.1
$ python -V; node -v; npm -v
Python 3.12.14
v26.13.0
12.2.2

$ python -m pytest -q
........................................................................ [ 97%]
.......................                                                  [100%]
795 passed, 17 skipped, 3 xfailed in 14.62s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
ok       tests/fixtures/acceptance/replay/strace_timestamp.log
ok       tests/fixtures/acceptance/replay/trace_pid_first.log
ok       tests/fixtures/acceptance/replay/file_events.log
ok       tests/fixtures/acceptance/replay/one_packet.pcap
ok       tests/fixtures/acceptance/replay/empty.pcap
ok       tests/fixtures/acceptance/replay/malformed.pcap

$ python scripts/verify_fixtures.py
replay/pcap-malformed        KNOWN-DEFECT  unreadable capture reported as an empty result (PCAP backend)

13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed

$ ruff check engine/ tests/ scripts/
All checks passed!
$ mypy engine/
Success: no issues found in 83 source files
$ hatchery rules lint
Rule lint passed

$ (cd server && npm ci && npm run typecheck && npm run build)
(no output: typecheck and build passed)

$ (cd server && npm test)
ℹ tests 97
ℹ pass 97
ℹ fail 0
ℹ skipped 0

$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
✔ a submission is queued, and a worker completes it into the API (946.099875ms)
✔ a job that cannot produce a bundle is reflected as failed, not running (711.458458ms)
✔ a database created before the queue gains the queue_job_id column (478.062083ms)
ℹ tests 3
ℹ pass 3
ℹ fail 0

$ (cd dashboard && npm ci && npm run build)
dist/index.html                   0.64 kB │ gzip:  0.44 kB
dist/assets/index-81vfRC8U.css   15.69 kB │ gzip:  4.03 kB
dist/assets/index-CwBji8IX.js   272.30 kB │ gzip: 84.69 kB
✓ built in 496ms

$ PYTHON=.../bin/python scripts/verify_setup.sh
HATCHERY baseline verification
repo:   /tmp/hatchery-phase4d-clean
python: Python 3.12.14 (/tmp/hatchery-phase4d-clean/.venv/bin/python)
node:   v26.13.0 / npm 12.2.2

PASS  python/package-installed           0.1.0
PASS  ports/free                         API (3002) and dashboard (5173) are available
PASS  fixtures/manifest                  checked-in fixtures regenerate byte-identically
PASS  fixtures/outcomes                  13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed
PASS  cli/submit-static                  bundle sha256 and EICAR rule recorded
PASS  store/encrypted-at-rest            content-addressed AES-256-GCM blob, 0600, no plaintext
PASS  server/npm-ci                      dependencies installed from the lockfile
PASS  server/build                       production build succeeded
PASS  dashboard/npm-ci                   dependencies installed from the lockfile
PASS  dashboard/build                    production build succeeded
PASS  api/compiled-start                 node dist/index.js answered /api/health
PASS  api/enqueue                        task 9cea6a32-103 queued (no subprocess held open)
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

Repository state: scripts/verify_setup.sh's own data/repository-untouched check
passed, and every server/dashboard test used temporary databases and stores.
Nothing outside /tmp was written.
```

### The commands, on a throwaway database

40 chained rows written through the real CLI (`token create`), then a compaction.

```text
$ HATCHERY_DB_PATH=/tmp/d32demo/data/hatchery.db npm run audit -- status --max-rows 20
database:     /tmp/d32demo/data/hatchery.db (167936 bytes)
rows:         40 total, 40 chained, 0 pre-chain
oldest:       1 at 2026-11-21T13:16:31.537Z
newest:       40 at 2026-11-21T13:16:35.064Z
archived:     0 row(s) in 0 segment(s)
policy:       {"older_than_seconds":null,"older_than":null,"max_rows":20,"keep_rows":1,"max_segment_rows":50000}
would move:   21 of 21 eligible row(s), ids 1-21
anchor row:   22 (stays live; the next row links through it)
growth:       ok — 40 rows, 167936 bytes; warn at 500000 rows / 268435456 bytes
append fails: 0 since start, 0 total
Retention is off by default and is applied only by `npm run audit -- compact --apply`.
The API never deletes an audit row: no timer, no background task, no request path.

$ npm run audit -- compact --max-rows 20
DRY RUN — nothing was written and no row was deleted.
would archive: 21 row(s), ids 1-21 (2026-11-21T13:16:31.537Z .. 2026-11-21T13:16:33.344Z)
archive:       /tmp/d32demo/data/audit-archives/<window>.jsonl
tail:          21:5641e3a76bf6f98e4af9f32f2aaf8e3cb9e11dc61889bc78341b585e728fead5
join:          the live row 22 links to that tail (proven)
remaining:     none

Re-run with --apply to archive the segment and delete exactly these rows.

$ npm run audit -- compact --max-rows 20 --apply
Archived 21 row(s), ids 1-21.
archive:   audit-archives/audit-000001-000021.jsonl (11469 bytes, sha256 4c39f5a4b890f1b77e1c0fb06c55413255aeae0286f93bc8444efc7fd1bcaa6f)
manifest:  audit-archives/audit-000001-000021.manifest.json (last written, sha256 8f3f7385d96ad2ae12ed5f1d24a305d006c209b695e55c47ff6206793a32b5c0)
tail:      21:5641e3a76bf6f98e4af9f32f2aaf8e3cb9e11dc61889bc78341b585e728fead5
join:      proven — the live chain resumes from that hash
remaining: none
Verify with `npm run audit -- verify` (reads the archive) or offline with
`npm run audit -- verify --archive audit-archives/audit-000001-000021.jsonl`.

$ npm run audit -- verify
ok:         true
assurance:  keyed (mac rows: 20, unkeyed: 0, pre-chain: 0)
rows:       20 live, 21 archived
head:       41:aea4e76c727c61813afe80f19a658ab507bc85dd58d5bd1bb5e4ce37d6f9afb2 (matches stored head: true)
archive:    1 segment(s) verified · manifest 8f3f7385d96ad2ae12ed5f1d24a305d006c209b695e55c47ff6206793a32b5c0 · join proven
anchor:     not supplied
growth:     ok — 20 rows, 217408 bytes
BREAK:      none
WARNING:    no failed appends recorded

$ npm run audit -- archives
  1  ids 1-21       21 rows  audit-archives/audit-000001-000021.jsonl
     manifest audit-archives/audit-000001-000021.manifest.json sha256:8f3f7385d96ad2ae12ed5f1d24a305d006c209b695e55c47ff6206793a32b5c0  tail 21:5641e3a76bf6f98e4af9f32f2aaf8e3cb9e11dc61889bc78341b585e728fead5

$ npm run audit -- head
41:aea4e76c727c61813afe80f19a658ab507bc85dd58d5bd1bb5e4ce37d6f9afb2
rows: 20 live, 21 archived in 1 segment(s)  key: e077858dd512e855
Record this somewhere the database writer cannot rewrite (a log collector, a ticket).

$ npm run audit -- verify --archive /tmp/d32demo/data/audit-archives/audit-000001-000021.jsonl
ok:         true
archive:    /tmp/d32demo/data/audit-archives/audit-000001-000021.jsonl
manifest:   /tmp/d32demo/data/audit-archives/audit-000001-000021.manifest.json
manifest#:  8f3f7385d96ad2ae12ed5f1d24a305d006c209b695e55c47ff6206793a32b5c0
archive#:   4c39f5a4b890f1b77e1c0fb06c55413255aeae0286f93bc8444efc7fd1bcaa6f
rows:       21
tail:       21:5641e3a76bf6f98e4af9f32f2aaf8e3cb9e11dc61889bc78341b585e728fead5
first prev: 0000000000000000000000000000000000000000000000000000000000000000
keys:       e077858dd512e855
BREAK:      none

The archive is internally consistent. Its tail is
  21:5641e3a76bf6f98e4af9f32f2aaf8e3cb9e11dc61889bc78341b585e728fead5
and a live chain whose first prev_hash equals that value continues it.
Its first row links to 0000000000000000000000000000000000000000000000000000000000000000 — the genesis value for
the first segment, or the previous segment's tail when splicing archives.
```

One archived row edited (its `path` changed), then verified offline:

```text
$ npm run audit -- verify --archive .../audit-000001-000021.jsonl
...
BREAK:      row 7 archive-modified: row 7 no longer hashes to its stored entry_hash (the manifest records archive sha256 4c39f5a4b890f1b77e1c0fb06c55413255aeae0286f93bc8444efc7fd1bcaa6f, the file hashes to 5a02d47248abc6037a6da7b38aa5118cb3e3c4e66cb8c0d290a461b7f08f88b1 — the file is not the one that was recorded)
exit 1

$ # restore the archive, then delete it
$ npm run audit -- verify
ok:         true
...
$ mv audit-000001-000021.jsonl /tmp/d32demo/hidden.jsonl
$ npm run audit -- verify
...
BREAK:      row 21 archive-missing: the chain records 1 archived segment(s) but 1 file(s) are missing: /tmp/d32demo/data/audit-archives/audit-000001-000021.jsonl — history has been removed, not archived
exit 1
```

## What was not verified

- **Compaction under a second writer of the same database.** Concurrent *appends* during
  a compaction are tested with a real 30-request burst, and a concurrent *compaction* is
  refused by the window re-check under the write lock — but two `compact` processes racing
  are not separately exercised end to end.
- **An archive on different storage.** A local directory was tested (`--out`, another
  directory). A network share's `fsync`/rename semantics are the storage's business and
  were not exercised.
- **An archive lost or stolen.** A missing archive is a break; an archive copied to an
  attacker (or leaked) is not something this slice can detect, and archives are not
  encrypted at rest. They are `0600`, owner-readable.
- **A wholesale replacement.** An attacker who can rewrite the archive **and** its
  manifest consistently can present a different internally consistent archive. What
  catches that is the tail hash recorded in `audit_chain_meta` and in the
  `audit.compacted` row, against a live database you still trust — not the archive alone,
  and not without an anchor recorded outside the database.
- **A root attacker.** Someone who can rewrite the database, the key ring, the archives
  and every backup consistently is out of scope, exactly as in D30/D31.
- **Clock skew.** `--older-than` is evaluated against the local clock. A skewed clock
  moves the retention boundary; it cannot corrupt the chain (timestamps are covered by the
  MAC, not monotonic).
- **An archive format change mid-stream.** `manifest_version: 1` only; a newer manifest is
  refused, not migrated.
- **Windows ACLs.** The `0600`/`0700` posture is POSIX and was verified on macOS only.
- **Archives of pre-D30 rows.** They are never archived (no `entry_hash`), so a database
  with a large pre-chain prefix keeps that prefix for ever.
- **Automatic or scheduled compaction.** Deliberately absent. Nothing compacts the log for
  you, and nothing warns twice.
- **The dashboard.** It has no retention or archive view; `/api/audit/verify` carries the
  data if one is added.
