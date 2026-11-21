# Sample store, encryption at rest and retention (D28)

This is the operator's guide to the Phase 4a sample store: what it guarantees,
what it deliberately does not, and the clean-copy evidence behind those claims.
The decision record is [`docs/DECISIONS.md`](DECISIONS.md) D28; the baseline
counts and the three known detector defects are in
[`docs/BASELINE.md`](BASELINE.md). Key rotation, retired keys and
backup/restore are Phase 4b (D29) and have their own operator guide and
clean-copy transcript in [`docs/BACKUP.md`](BACKUP.md); this page describes the
store's storage and retention guarantees, which D29 does not replace.

## One store, one root

Every entry point — `hatchery submit`, `submit --enqueue`, `hatchery worker`,
`hatchery replay` and `hatchery store` — uses `engine/store/`. There is no second
implementation. The root is, in order:

1. `--store PATH` / the explicit argument;
2. `HATCHERY_SAMPLE_STORE`;
3. `<checkout>/samples` (the directory the pre-D28 plaintext store used), where
   the checkout is the one that owns the installed `engine` package;
4. `./samples` for a non-checkout install.

The root is resolved **absolutely**, so a CLI run, the API's enqueue and a worker
started from three different directories agree. Before D28 the path was relative
to the working directory, which produced three different stores on one machine.

## What the store guarantees

| Property | Guarantee |
|:--|:--|
| Addressing | Blob name is the plaintext SHA-256; the hash is re-checked on every read and a mismatch is refused |
| Confidentiality at rest | AES-256-GCM envelope, 0600 blobs, no write path emits plaintext |
| Integrity | The envelope header (magic, version, key id, nonce, length) is authenticated as additional data; a tampered header fails exactly like tampered ciphertext |
| Atomicity | Ciphertext temp → `fsync` → atomic rename → directory `fsync` → index row. A crash leaves the old blob or the new one, never a half-written sample |
| Index | SQLite, WAL, `BEGIN IMMEDIATE`; a **cache** of the blobs, repaired by `reconcile` (adopt orphan, drop missing, repair encryption drift, revert an interrupted delete, clean stale temporaries) |
| Failure reasons | `no-key`, `key-invalid`, `key-file-missing`, `key-file-permissions`, `key-file-symlink`, `not-found`, `symlink`, `not-a-file`, `too-large`, `unknown-version`, `truncated`, `wrong-key`, `auth-failed`, `hash-mismatch`, `legacy-hash-mismatch` — each distinct, none containing key material |
| Retention | TTL explicit and **off by default**; prune is a dry run unless `--apply`; every decision carries a reason |
| References | A sample referenced by a run bundle or a queued/running job is never deleted; an unidentifiable queued job makes `--apply` refuse |
| Concurrency | Atomic writes; prune/migrate/verify hold a non-blocking `flock`; a prune that races a reader leaves the reader a clean `not-found`, never a torn file |

### Envelope format (version 1)

```
b"HATCHERY-SAMPLE\x00"   16 bytes magic
version                   u8   = 1
key_id                    8 bytes  = sha256("hatchery-sample-key\x00" + key)[:8]
nonce                    12 bytes  (random per write)
plaintext_len             u64 big-endian
ciphertext + GCM tag      plaintext_len + 16 bytes
```

AAD is the whole header. Because the key id is inside the authenticated header,
a wrong key is reported as `wrong-key` (with both ids) rather than as corruption;
a modified key id, nonce, version or length is `auth-failed`/`unknown-version`;
a short file is `truncated`. Decryption verifies the plaintext SHA-256 against
the address before any caller sees bytes.

### Keys

- `HATCHERY_SAMPLE_KEY` — 32 bytes as 64 hex characters or base64.
- `HATCHERY_SAMPLE_KEY_FILE` — path to a 32-byte key file. It must be a regular
  file, not a symlink, with no group/other permission bits; otherwise it is
  refused.
- Neither configured → the first write generates `<store>/.sample-key` (0600,
  `O_EXCL`, race-safe) and announces it on stderr (`WARNING: generated a new
  local sample-encryption key at ...`) and in `store status`. There is no silent
  plaintext fallback.
- `hatchery store keygen -o PATH` creates a key file for an operator who wants
  it outside the store; it prints the path and the key **id**, never the key.
- The key is never written to the index, a bundle, a report, argv, a log or an
  error message. Only the key id (a one-way hash prefix) is stored and printed.

**Key in the store directory.** The generated key lives beside the ciphertext.
It protects against plaintext at rest — backups, snapshots, a copied directory,
a `grep` over the disk — **not** against an attacker who can read the store
directory. For that posture, set `HATCHERY_SAMPLE_KEY_FILE` to a path outside the
store (or supply the key from a secret manager) and keep the file 0600.

**Losing the key** means the samples cannot be decrypted. `store verify` reports
`no-key`/`wrong-key`, and replay of a store-only sample is INCONCLUSIVE. The fix
is to restore the key, not to delete the store.

## Retention and references

- `--ttl SECONDS` or `HATCHERY_SAMPLE_TTL`. `0` (or unset) disables expiry.
- The age is `now - max(stored_at, last_referenced_at)`; a reference scan moves
  `last_referenced_at` forward, so the TTL clock starts when a sample was last
  observed in use, not when it happened to be stored.
- `prune` **always** re-reads the references before deciding:

  | Source | What it reads |
  |:--|:--|
  | Run bundles | `sample.sha256` in `<results>/<run>/bundle/analysis.json` and `<results>/<run>/<replay>/bundle/analysis.json`, for every root in `--results`, `HATCHERY_RESULTS_ROOT`/`HATCHERY_RESULTS_DIR`, `<checkout>/results` and `./results` |
  | D27 queue | jobs in `queued` or `running`, by `sample_store_ref`/`sample_sha256`; a pre-D28 job by hashing the original path it still points at |

- Dry run (default) reports `would_delete`; `--apply` deletes. Each entry says
  `decision` (`keep`/`delete`), `reason` (`referenced`, `ttl-disabled`,
  `not-expired`, `expired`), its age and the reference labels.
- **Fail closed on ambiguity.** If a queued/running job's sample cannot be
  identified (no address and an unreadable path), `prune --apply` refuses and
  exits 2 without deleting anything.
- **The results-root list is part of the contract.** A bundle outside every
  scanned root is invisible; the operator must point `--results` at the archive
  that still needs the sample. The demo below shows this explicitly.
- `prune` never deletes a result bundle. Bundles have their own retention now
  (D33) and `store prune` still only reads them for references — see
  [Result bundles (D33)](#result-bundles-d33) below.

## Result bundles (D33)

`results/<run>/` is the artifact an analyst hands to a client, and it now
describes itself: a deterministic SHA-256 manifest at the run root, written last
by every stage that touches the run (`submit`, `triage`, `push`, `replay`). D28's
reference scan reads `bundle/analysis.json` and is unchanged, so the two controls
compose: pruning a bundle releases a sample only when nothing else references it.

```bash
hatchery results verify results/<run>                       # intact / unsealed / broken + path
hatchery results seal results/<run>                         # legacy run -> verifiable (idempotent)
hatchery results verify results/<run> --expect-manifest SHA # the anchor you recorded at delivery
hatchery results status                                     # runs, bytes, oldest/newest, strays, growth
hatchery results prune --older-than 30d --keep-last 5       # dry run: exactly what would go
hatchery results prune --older-than 30d --keep-last 5 --apply
```

- **Retention is off by default and operator-applied.** Nothing in `submit`, the
  worker or the API deletes a run; there is no timer.
- **A run that cannot be verified is never deleted.** `--apply` refuses the whole
  plan and exits 2 when a run has no manifest, an invalid manifest or an
  unparseable bundle — seal the corpus first.
- **The newest `--keep-last` runs are always kept** (`1` by default, clamped to at
  least 1); a policy that would delete every run reports `clamped: true`.
- **Rename, then remove**, so a crash leaves a resumable `.deleting-` stray rather
  than a half-deleted tree.
- **Pruning a bundle changes what the sample store may delete.** After pruning run
  A, a sample referenced only by A becomes prunable by `hatchery store prune`; a
  sample still referenced by run B or by a queued/running job remains protected.
  `store prune` was not modified to achieve this — its reference scan is the
  authority — and both directions are tested.

The operator guide, the failure classifications and the clean-copy transcript are
in [`RESULTS.md`](RESULTS.md). The decision is D33.

## Queue coupling (D27)

- `--enqueue` copies the accepted bytes into the store **before** the job row is
  written and records `sample_sha256` + `sample_store_ref`.
- The worker runs `submit --from-store <sha>`; the original path is kept only as
  an informational hint in the bundle. **Deleting the original after enqueue no
  longer breaks the job.**
- A pre-D28 job is adopted on claim (hashed, copied, reference recorded) or by
  `hatchery store migrate --queue PATH`. If neither the store copy nor the
  original exists, the job fails with the reason — never silently dropped and
  never reported successful.
- The queue schema is migrated with `PRAGMA user_version` 0→2 and an additive
  `ALTER TABLE`; job ids, states, attempts and leases are preserved. A queue
  written by a newer build is refused.
- The queue is still the only writer of job state; the store is the only writer
  of sample state. The job holds an address, not a copy of the index.

## Replay coupling (D26)

- Replay asks the store first (then the recorded path). Once the store owns an
  address it is authoritative: pruned (`not-found`), expired (`expired`), wrong
  key (`wrong-key`), tampered (`auth-failed`), truncated (`truncated`) or a
  content mismatch (`hash-mismatch`) is **INCONCLUSIVE** with that reason — never
  a pass, never a traceback, and never a silent fallback to another copy.
- Decryption is in memory. The path-based pipeline (YARA, capa, delivery,
  `put_archive`) still needs a file, so replay/submit hand it a **single-use
  staging file**: a fresh 0700 directory under the system temp dir, a 0600 file
  written with `O_EXCL`, unlinked in `finally` and at interpreter exit. No
  plaintext is written into the store, the index or the results tree.
- **Known gap:** SIGKILL or power loss between write and unlink can leave that
  staging file in the OS temp directory. Removing the staging file entirely
  means teaching every analyser to read bytes instead of paths — a larger change
  than this slice, and one that would touch D4's single-producer pipeline.
- Replay's default store is opened **read-only**: a replay does not create the
  store directory, the index or a key just by looking for a sample.

## CLI reference

```
hatchery store status    [--ttl N] [--json] [--store DIR] [--results DIR] [--queue PATH]
hatchery store verify    [--sha SHA] [--json] ...
hatchery store migrate   [--dry-run] [--adopt-queue/--no-adopt-queue] [--json] ...
hatchery store prune     [--apply] [--ttl N] [--json] ...
hatchery store keygen    -o PATH
hatchery store key status|rotate|retire   # D29: key ring, rotation, retirement
hatchery store backup    -o DIR [--include-key] [--queue PATH]
hatchery store restore   BACKUP --target DIR [--force]
```

The D29 commands keep the same contract (JSON on stdout, diagnostics on stderr,
0/1/2) and are documented in [`docs/BACKUP.md`](BACKUP.md).

JSON goes to **stdout** (one object), diagnostics go to **stderr** (the group
routes the Rich log handler to stderr so an INFO line cannot corrupt the JSON).
Exit codes: **0** success; **1** operational error (bad key, lock held, IO);
**2** verification or retention failure, including a refused prune. A legacy
plaintext entry is a `verify` failure with reason `plaintext-legacy` until
`migrate` encrypts it. No command prints a key.

## Common operations

```bash
# First run on a fresh host: let the store generate its key, then back it up.
hatchery submit sample.elf --no-sandbox -o results/first
hatchery store status --json | jq .key         # source, key id, warning

# Prefer an operator-held key (outside the store).
hatchery store keygen -o ~/.hatchery/sample.key
export HATCHERY_SAMPLE_KEY_FILE=~/.hatchery/sample.key

# Audit the store.
hatchery store verify --json                   # exit 2 on any failure
hatchery store status --json | jq '.legacy_plaintext, .reclaimable'

# Adopt an old plaintext store (idempotent, resumable).
hatchery store migrate                         # encrypts; --dry-run first if you like
hatchery store migrate --queue data/queue.db   # also adopt pre-D28 queued jobs

# Retention: dry run, read the reasons, then apply.
hatchery store prune --ttl 2592000
hatchery store prune --ttl 2592000 --apply
```

## What was not verified

- **Key rotation, retired keys, backup and restore.** ✅ Built in Phase 4b
  (D29); see [`docs/BACKUP.md`](BACKUP.md) for the key-ring format, rotation
  resumability, backup manifest and restore validation, and the clean-copy
  transcript. What remains undone there: KMS/HSM/escrow, multi-host rotation,
  scheduled rotation/expiry, secure erase, a signed manifest, and disaster
  recovery of a destroyed key.
- **KMS/HSM, network key services, a daemon, a new network surface.** None was
  added; the key is an env var, a local file or the store's `0600` ring.
- **Multi-host.** The store is a local directory and the reference scan reads
  this host's results roots and queue only. A bundle on another machine is not
  consulted (and is therefore not protected). D29's rotation and backup are
  single-host for the same reason.
- **Platform-specific file permissions.** `0600`/`0700` and `O_EXCL` are exercised
  on macOS 27 / APFS in this baseline (and Linux in CI); Windows ACLs are not.
- **Crash injection at the syscall boundary.** Atomicity is tested by fault
  injection (`os.replace` raising, orphan/missing blobs, interrupted deletes and
  migration), not by killing a process mid-`fsync`.
- **Live key compromise / forensic recovery of a deleted blob.** Deleting a blob
  is `unlink` + index delete; there is no secure-erase claim.
- **Result-bundle retention.** ✅ Built in Phase 4e (D33): a manifest at the run
  root, `hatchery results verify|seal|status|prune`, off-by-default retention and
  the growth guard — see [`RESULTS.md`](RESULTS.md). What remains undone there:
  signing/MAC'ing the manifest (an artifact and its manifest rewritten together
  are caught only by an operator-recorded anchor) and **encrypting `results/` at
  rest**. `store prune` still never deletes a bundle; it only reads references.
- **Extracted delivery children and emulation artifacts.** They live in the run
  directory and remain plaintext, like the rest of `results/`.

## Captured transcript

Clean copy of the repository at commit `be9386d`, no `.venv`, `node_modules`,
`data/`, `results/`, `uploads/` or caches. The only deviation from the literal
protocol is that Python 3.12 is invoked through the interpreter uv had already
installed (`cpython-3.12.14`) rather than a `python3.12` on `PATH`; `python -V`
in the transcript confirms 3.12.14.

```text
# HATCHERY Phase 4a — clean-copy verification transcript

Captured: 2026-11-21T10:22:42Z (UTC)
Source: git clone of the repository at the D28 code commit, checked out at
        be9386d, with no .venv, node_modules, data/, results/, uploads/ or caches

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
.......................................................................  [100%]
771 passed, 17 skipped, 3 xfailed in 17.23s

$ python tests/fixtures/acceptance/tools/generate_fixtures.py --check
ok       tests/fixtures/acceptance/replay/empty.pcap
ok       tests/fixtures/acceptance/replay/malformed.pcap
$ python scripts/verify_fixtures.py

13 passed, 0 failed, 3 known defects, 0 unverified, 0 changed

$ ruff check engine/ tests/ scripts/
All checks passed!
$ mypy engine/
Success: no issues found in 82 source files
$ hatchery rules lint
Rule lint passed

$ scripts/verify_setup.sh
HATCHERY baseline verification
repo:   /tmp/hatchery-phase4a-clean
python: Python 3.12.14 (/private/tmp/hatchery-phase4a-clean/.venv/bin/python3)
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
PASS  api/enqueue                        task 6154ec8b-cc4 queued (no subprocess held open)
PASS  api/restart-durability             task survived an API restart
PASS  worker/executes-job                worker drained the queue and exited 0
PASS  worker/store-backed-job            job records a content address and completed from it
PASS  api/ingest-after-worker            completed task has the expected hash and static results
PASS  dashboard/dev-server               http://localhost:5173/ returned 200
PASS  dashboard/api-proxy                /api/health proxied to the API
PASS  data/repository-untouched          databases, results, uploads and EICAR unchanged

RESULT: baseline verified

$ (cd server && npm ci && npm run typecheck && npm run build && npm test)
✔ failed clone (negative return) creates no child (0.246417ms)
ℹ tests 34
ℹ pass 34
ℹ fail 0
ℹ skipped 0

$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
✔ a submission is queued, and a worker completes it into the API (1338.578042ms)
✔ a job that cannot produce a bundle is reflected as failed, not running (932.19275ms)
✔ a database created before the queue gains the queue_job_id column (477.7315ms)
ℹ tests 3
ℹ pass 3
ℹ fail 0
ℹ skipped 0

$ (cd dashboard && npm ci && npm run build)
dist/assets/index-CwBji8IX.js   272.30 kB │ gzip: 84.69 kB
✓ built in 510ms

=== sample store: live commands against temporary roots ===

$ hatchery store status --json --results results/   # the run now references the stored sample
{"samples": 1, "bytes": 68, "encrypted": 1, "legacy_plaintext": 0, "expired": 0, "referenced": 1, "reclaimable": 0}
referenced_by: ['run:run']

$ hatchery store verify --json
{"ok": true, "checked": 1, "failed": 0, "legacy": 0}

$ hatchery replay results/run/bundle --no-sandbox -o replay   # original path deleted
│ Verdict:  reproducible                                                       │
- Sample resolved via sample store 

$ hatchery store prune --ttl 0.001            # dry run; the run bundle still references it
{"applied": false, "summary": {"kept": 1, "deleted": 0, "would_delete": 0, "refused": 0}, "kept_reason": "referenced", "kept_by": ["run:run"]}

# The bundle is moved outside the scanned results root: nothing the scan can see
# references the sample any more, so it is expired and prunable. This is why the
# results-root list is part of the operator contract.
$ hatchery store prune --ttl 0.001 --apply
{"summary": {"kept": 0, "deleted": 1, "would_delete": 0, "errors": 0}, "deleted": ["275a021bbfb6489e"]}

$ hatchery replay archive/run/bundle   # after the purge: INCONCLUSIVE, never a pass
exit=1
{"verdict": "inconclusive", "reason": "not-found", "hash_verified": false}

$ hatchery store migrate   # pre-D28 plaintext -> encrypted, then idempotent
before migrate: legacy = 1
verify before migrate: exit=2
[11/21/26 07:23:30] INFO     Stored sample ee653f4902ad829f (23 bytes,          
                             aes-256-gcm/v1, source migrate:ee653f4902ad829f)   
migrated: ['ee653f4902ad829f'] failed: 0
second run: legacy_found = 0 encrypted = 0
verify after migrate: ok = True checked = 1

=== repository state after every gate ===
(clean: no repository data/, results/, uploads/ or samples/ file was created)
```
