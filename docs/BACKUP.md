# Key lifecycle, rotation and recoverable backups (D29)

This is the operator's guide to Phase 4b: the key ring, per-blob key
resolution, rotation and retirement of a leaked key, and a backup/restore that
can be trusted enough to delete the original. The decision record is
[`DECISIONS.md`](DECISIONS.md) D29; D28 remains authoritative for the envelope
and the store, D27 for job state. The clean-copy transcript is at the end of
this page.

The phase exists because D28's store had one active key and no recovery story.
A leaked key could not be rotated, a backup that omitted `<store>/.sample-key`
looked fine but was worthless, `cp` against a live WAL database could be torn,
and a partially rotated store had no safe read path. None of that is a feature
request; each is a way an operator loses samples while believing they are safe.

## Key ring

A store may have an optional **key ring** at `<store>/.sample-keyring`:

```json
{
  "version": 1,
  "active": "<16-hex key id>",
  "rotation": {"in_progress": false, "started_at": null, "from": null},
  "keys": [
    {"id": "<16-hex key id>", "material": "<base64 of 32 bytes>", "created_at": "..."}
  ]
}
```

- It is written `0600`, at most 64 KiB and 32 keys. A version newer than this
  build understands is refused (`key-ring-version`); it is read with the same
  rules as a key file (regular, non-symlink, no group/other bits).
- **The ring is authoritative once it exists.** A stale `HATCHERY_SAMPLE_KEY`
  is reported as `env_ignored` and does not out-vote the store's own record.
  With no ring, resolution is exactly D28's order: `HATCHERY_SAMPLE_KEY`, then
  `HATCHERY_SAMPLE_KEY_FILE` / `<store>/.sample-key`, then the generated local
  key (still announced). A D28 store needs no migration.
- **Resolution is by id.** The envelope names its key id; decryption looks that
  id up in the ring. There is no trial decryption. A blob naming a key the ring
  does not hold fails `unknown-key-id`, naming the key id **and the blob**;
  the blob is left byte-identical. A D28 single configured key keeps its
  `wrong-key` reason. `no-key` means nothing is configured at all.
- **Only the key id is printable.** Key material is never written to the index,
  a bundle, a report, argv, a log, an error message, `store status`, `store
  verify` or a backup manifest.

The key still lives beside the ciphertext in the default posture (generated
`.sample-key` or the ring itself). It protects against plaintext at rest —
backups, snapshots, a copied directory — **not** against an attacker who can
read the store directory. Point `HATCHERY_SAMPLE_KEY_FILE` outside the store,
or use a secret manager, when that distinction matters.

## Rotation and retirement

```text
hatchery store key status  [--json] [--store DIR] [--results DIR] [--queue PATH]
hatchery store key rotate  [--dry-run] [--key-file PATH] [--json] ...
hatchery store key retire  KEY_ID [--json] ...
```

`rotate`:

1. takes `<store>/.store.lock` (non-blocking — a second rotation reports
   `store-locked`, so two rotations cannot interleave);
2. reconciles the index from the blobs (the blobs are the truth);
3. generates a new key, or loads `--key-file` (a `0600`, non-symlink 32-byte key
   file), and writes the ring with both keys and `rotation.in_progress: true`
   **before touching any blob** — from that instant a reader holds both keys;
4. re-wraps every blob whose envelope key id is not the active id: resolve the
   key the envelope names, authenticate, verify the plaintext SHA-256 against the
   content address, re-encrypt under the active key, write with
   ciphertext-temp → `fsync` → atomic rename → directory `fsync`, then update the
   index row;
5. re-reads the blob headers and clears `rotation.in_progress` only when **no
   blob references a retired key**.

Properties that matter:

- **Resumable.** A crash between any two operations leaves the ring and blobs
  readable. The next `rotate` (no `--key-file`) sees `rotation.in_progress`,
  resumes the same active key, reconciles from the blobs and finishes. It does
  not generate another key and it does not restart from an assumption. A crash
  after a rename but before the index update is repaired by `reconcile`, which
  compares the row's key id with the blob's authenticated header.
- **Fail closed per blob.** A missing retired key, a corrupt blob, a truncated
  envelope or a content-address mismatch is recorded per blob and left
  untouched; the command exits 2 and names the blob. Rotation never deletes or
  rewrites bytes it cannot verify.
- **Complete only on one key.** `store status`, `store verify` and
  `store key status` report the active key id, `per_key_blob_counts`,
  `rotation_complete`, `rotation_pending` and `rotation_in_progress`.
- **Retirement is explicit.** `retire KEY_ID` removes a retired key, and is
  refused while any blob header still names it (`key-in-use`, exit 2) and for
  the active key (`key-is-active`). This is what makes a rotation
  irreversible — do it only after `rotation_complete` is true.
- `--dry-run` reports what would move, and what is blocked by a missing key,
  without writing a ring or a blob.

Reader safety: `read`/`replay` take no store lock. While rotation runs, a read
either succeeds (the ring has both keys) or fails with a precise reason; the
atomic rename means it never sees a torn file. A replay is still INCONCLUSIVE,
never a pass, when a sample is purged, expired, wrong-key, unknown-key-id or
corrupt.

## Backup

```text
hatchery store backup --output DIR [--include-key] [--queue PATH] [--store DIR] [--json]
```

Layout:

```text
DIR/
├── manifest.json                 # written last (temp + fsync + rename)
├── store/
│   ├── index.db                  # SQLite backup API, consistent while live
│   └── blobs/<sha256>.sample     # ciphertext, streamed and hashed while copied
├── queue/queue.db                # SQLite backup API, if a queue was given
└── secrets/sample-keyring        # only with --include-key, 0600
```

- **Only what cannot be regenerated.** Result bundles, `uploads/`, delivery
  children and the replay staging file are deliberately excluded and the
  manifest says so. `results/` is plaintext and is regenerable only by a re-run.
- **SQLite's backup API for every live database** (index and queue), never a
  file copy of a WAL database. The store lock is taken with a bounded wait so a
  prune finishes first rather than the backup racing it; `put` only adds blobs,
  and the index snapshot is copied before the blobs it names, so a live writer
  produces a consistent point-in-time backup.
- **The manifest is written last.** An interrupted backup has no `manifest.json`
  and cannot be mistaken for a complete one; a rerun into the same directory
  completes it. The manifest records `format`/`manifest_version`,
  `created_at`, schema versions (manifest, index, queue, envelope, key ring),
  counts and sizes, per-file SHA-256 (plus each blob's content address,
  envelope version and key id), the key ids present, whether a key is included,
  and `restorable_without_operator_key`.
- **The key is excluded by default.** `--include-key` is explicit, writes the
  ring `0600` inside the backup, warns loudly on stderr, and makes the manifest
  say a secret is present. The manifest itself never contains key material.
- A legacy plaintext blob is refused (`backup-failed`, exit 2) — a backup must
  not be the thing that copies plaintext malware somewhere new. Run
  `hatchery store migrate` first.
- An empty default queue file is skipped with a warning; a non-empty file with
  no `jobs` table is refused rather than copied as if it were a queue.

## Restore

```text
hatchery store restore BACKUP --target ROOT [--force] [--queue PATH] [--store PATH] [--json]
```

The store is restored to `ROOT/samples` and the queue to `ROOT/queue.db`
(overridable). The backup is **hostile input**: everything is validated before
a byte is written.

- Manifest exists, is the right format/version, has consistent counts and states
  whether a key is included. Newer manifest or schema versions are refused.
- Every path is relative, has no `.`/`..`/absolute segment, matches the allowed
  layout and is not a symlink at any component. Traversal is refused.
- Every size is bounds-checked and every file hash matches the manifest.
- The index and queue pass `integrity_check`, are not newer than this build, and
  the index row set equals the blob set (a torn backup is refused).
- Every blob's envelope version, key id and content address are checked, and
  every blob is authenticated and plaintext-hash-verified **in memory** when its
  key is available. A corrupt blob writes nothing.
- A non-empty target is refused unless `--force`; even with `--force`, a blob
  whose bytes differ is never overwritten.
- Index rows and queue job ids, states, attempts and `sample_store_ref` are
  preserved, not re-derived. A queued/running job whose restored sample is
  absent is reported (and will fail in the worker with that precise reason) —
  never silently requeued with no sample.
- After writing, the normal `SampleStore.verify` runs. Files restored but
  undecryptable because a key id is not configured are reported per blob
  ("restored, but key id X is not configured") and the command exits **2**; it
  never declares success it cannot support. Supplying
  `HATCHERY_SAMPLE_KEY`/`HATCHERY_SAMPLE_KEY_FILE` and re-running `store verify`
  completes the recovery.

## CLI reference and exit codes

| Command | What it does |
|:--|:--|
| `store key status` | active key id, ring, retired keys, per-key blob counts, rotation completeness |
| `store key rotate` | generate/accept a new active key and re-wrap every non-active blob (resumable, atomic per blob) |
| `store key retire KEY_ID` | remove a retired key; refused while any blob needs it or if it is active |
| `store backup` | blobs + index + queue, SQLite backup API, hashed, manifest last, key excluded by default |
| `store restore` | validate the backup as hostile input, restore into a new root, verify every entry, preserve job state |

Every subcommand accepts `--json` (one object on **stdout**; diagnostics on
**stderr**) and the store group routes the Rich log handler to stderr, so an
INFO line cannot corrupt the JSON. No command prints key material.

Exit codes: **0** success; **1** operational error or a refusal that wrote
nothing (bad key, lock held, non-empty target, invalid/traversing manifest,
schema newer, tampered blob); **2** a verification/state failure (rotation
incomplete or per-blob failure, a refused retirement, a backup refused because
the store still holds plaintext, a restore that completed with undecryptable
entries or a job whose sample is missing).

## Common operations

```bash
# A leaked key: rotate, verify, then retire the old key explicitly.
hatchery store key status                       # note the active id and counts
hatchery store key rotate --json | jq '{complete, rotated: (.rotated|length), failed, per_key_blob_counts}'
hatchery store verify --json                    # exit 2 on any failure
hatchery store key status --json | jq .rotation # rotation_complete must be true
hatchery store key retire <old-key-id>          # refused while a blob needs it

# A backup an operator can actually restore.
hatchery store verify --json                    # do not back up a broken store
hatchery store backup -o /secure/backups/2026-11-21 --queue data/queue.db
# (add --include-key only when the backup medium is protected like the key)
hatchery store restore /secure/backups/2026-11-21 --target /srv/hatchery-restore
HATCHERY_SAMPLE_STORE=/srv/hatchery-restore/samples \
HATCHERY_QUEUE_DB=/srv/hatchery-restore/queue.db \
  hatchery store verify --json
```

An interrupted rotation is resumed by running `store key rotate` again (it sees
`rotation.in_progress`). An interrupted backup has no manifest; rerun it. A
restored queued/running job either runs from its store reference or fails with
the reason; it is never silently requeued with no sample.

## What was not verified

- **KMS/HSM, a network key service, escrow or split-key.** None was added; the
  ring is a local `0600` file.
- **Multi-host rotation or a coordinated backup across hosts.** The store and
  queue are single-host files; another host's blobs are invisible.
- **Scheduled rotation, key expiry, automatic retirement.** Rotation and
  retirement are operator actions.
- **Secure erase.** Removing a key from the ring does not wipe its bytes from
  disk, snapshots or backups that already included it.
- **Disaster recovery of a destroyed key.** If every copy is gone, its blobs
  are unrecoverable; `verify` says `unknown-key-id`/`no-key` and the phase does
  not invent a path.
- **Backup of `results/`, `uploads/`, delivery children or the replay staging
  file.** Result bundles remain plaintext and are out of scope; this slice only
  backs up and restores the store and queue.
- **A signed manifest.** Blob authentication and manifest/file hashes are
  checked, but an attacker who can rewrite the whole backup consistently can
  present a different backup. The manifest is not signed.
- **Windows ACLs.** `0600`/`0700`/`O_EXCL` are exercised on macOS/APFS in this
  baseline (and Linux in CI); Windows ACLs are not verified.
- **Crash injection at the syscall boundary.** Interruption is simulated by
  fault injection (a crash after rename before the index update, a crash
  mid-store, a manifest write that fails), not by killing a process
  mid-`fsync`.

## Captured transcript

Clean copy of the repository at the D29 code commit `34565f7`, with no `.venv`,
`node_modules`, `data/`, `results/`, `uploads/` or caches. The literal protocol
uses `python3.12`; the only deviation is that the interpreter uv had already
installed (`cpython-3.12.14`) was used directly, and `python -V` in the
transcript confirms 3.12.14. Later docs-only commits do not change the code
under test.

```text
# HATCHERY Phase 4b — clean-copy verification transcript

Captured: 2026-11-21T11:10:00Z (UTC)
Source: git archive 34565f7 (D29 code commit), unpacked into
        /tmp/hatchery-phase4b-clean; no .venv, node_modules, data/, results/,
        uploads/ or caches in the archive.

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
795 passed, 17 skipped, 3 xfailed in 21.51s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
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

$ (cd server && npm ci && npm run typecheck && npm run build && npm test)
ℹ tests 34
ℹ pass 34
ℹ fail 0
ℹ skipped 0

$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
✔ a submission is queued, and a worker completes it into the API
✔ a job that cannot produce a bundle is reflected as failed, not running
✔ a database created before the queue gains the queue_job_id column
ℹ tests 3
ℹ pass 3
ℹ fail 0

$ (cd dashboard && npm ci && npm run build)
dist/assets/index-CwBji8IX.js   272.30 kB │ gzip: 84.69 kB
✓ built in 502ms

$ PYTHON=.venv/bin/python scripts/verify_setup.sh
HATCHERY baseline verification
repo:   /tmp/hatchery-phase4b-clean
python: Python 3.12.14 (/tmp/hatchery-phase4b-clean/.venv/bin/python)
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
PASS  api/enqueue                        task d808a73c-cc6 queued (no subprocess held open)
PASS  api/restart-durability             task survived an API restart
PASS  worker/executes-job                worker drained the queue and exited 0
PASS  worker/store-backed-job            job records a content address and completed from it
PASS  api/ingest-after-worker            completed task has the expected hash and static results
PASS  store/key-rotation                 every blob re-wrapped; verify passes on the new active key
PASS  store/backup-restore               manifest hashes every blob; restored job ids and samples verify
PASS  dashboard/dev-server               http://localhost:5173/ returned 200
PASS  dashboard/api-proxy                /api/health proxied to the API
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged

RESULT: baseline verified

=== D29 live commands against temporary roots ===

$ hatchery submit samples/eicar.com --no-sandbox -o /tmp/hatchery-d29-demo/run
exit=0
$ hatchery store key status --json
{"active_key_id": "5241a68e7f22c222", "per_key_blob_counts": {"5241a68e7f22c222": 1}, "retired": [], "ring": false, "rotation_complete": true}
$ hatchery store key rotate --json
exit=0
{"active_after": "3b4da9e44e93fa35", "active_before": "5241a68e7f22c222", "complete": true, "failed": 0, "mode": "rotate", "per_key_blob_counts": {"3b4da9e44e93fa35": 1}, "rotated": 1}
$ hatchery store verify --json
exit=0
{"active_key_id": "3b4da9e44e93fa35", "checked": 1, "ok": true, "per_key_blob_counts": {"3b4da9e44e93fa35": 1}, "rotation_complete": true}
$ hatchery store key rotate --json   # a second rotation: new active, previous retired
exit=0
{"complete": true, "mode": "rotate", "per_key_blob_counts": {"45e4ab27ccc6066a": 1}, "rotated": 1}
$ hatchery store backup --json --include-key -o /tmp/hatchery-d29-demo/backup --queue /tmp/hatchery-d29-demo/none.db
exit=0
{"blob_entries": 1, "counts": {"blobs_bytes": 129, "index_present": true, "queue_by_status": {}, "queue_jobs": 0, "queue_present": false, "samples": 1}, "excluded": 4, "key_ids": ["3b4da9e44e93fa35", "45e4ab27ccc6066a", "5241a68e7f22c222"], "key_included": true, "manifest_version": 1, "restorable_without_operator_key": true}
stderr warning: WARNING: the sample-encryption key ring is INCLUDED in this backup (secrets/sample-keyring, mode 0600). Anyone who can read the backup can decrypt every sample in it. Store it accordingly and never commit it.
backup key ring mode: 0o600
$ hatchery store restore /tmp/hatchery-d29-demo/backup --target /tmp/hatchery-d29-demo/restored --json
exit=0
{"ok": true, "samples": 1, "store_root": "/private/tmp/hatchery-d29-demo/restored/samples", "undecryptable": 0, "verify_ok": true}
$ hatchery store verify --json   # against the restored store
exit=0
{"checked": 1, "ok": true, "rotation_complete": true}
$ hatchery store restore ...   # second time into the same non-empty root
exit=1
{"ok": false, "reason": "restore-target-not-empty", "message": "... is not empty; restore into a new root or pass --force (which still never overwrites a blob whose bytes differ)"}
no key material on stdout/stderr: yes

=== repository state after every gate ===
(clean: no repository data/, results/, uploads/ or samples/ file was created)
```
