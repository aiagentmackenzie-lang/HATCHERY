# Security Policy

## Reporting

Open a private security advisory on the repository, or contact the maintainer directly. Do not open a public issue for anything exploitable.

## What this project is, security-wise

HATCHERY **runs untrusted code**. That is its job. Treat every part of it accordingly.

The isolation boundary comes from the host, not from this code, and `hatchery doctor` reports which tier is in force. Tier 1 (`shared-kernel`, plain containers) is **not** a security boundary: the sample shares your kernel, and one kernel vulnerability reachable through an allowed syscall is enough. Run samples you do not trust only at tier 2 (gVisor) or tier 3 (microVM), on a machine you are willing to lose.

The seccomp profile in `engine/sandbox/seccomp.json` is a deny-list and is therefore **hardening, not isolation**. It must permit `ptrace`, because the sandbox observes behavior with `strace`; a profile that denies `ptrace` silently disables monitoring. `tests/test_seccomp.py` enforces that contract.

## Delivery-format intake

A delivery container is untrusted input that HATCHERY deliberately parses. `engine/intake/delivery.py` is bounded: depth 3, at most 64 children, 64 MiB per member, 256 MiB uncompressed, a 200:1 compression-ratio guard, and refusal of symlink/device and encrypted members. Member names are flattened under `results/<task_id>/delivery/`, so an archive cannot write outside it. Extraction never executes anything. ZIP/OOXML, tar/gzip/bzip2/xz, HTML/SVG, Windows shell links (LNK), ISO9660/IMG, PDF, legacy Office OLE/CFB compound files and RTF embedded objects are parsed. Formats that are detected but not extracted (7z, RAR, CAB) are reported as unsupported with a reason instead of being silently ignored. The LNK, ISO9660 and PDF parsers are exercised in tests against container bytes written by independent libraries (`pylnk3`, `pycdlib`, `pypdf`); the OLE/CFB parser against `olefile` (independent CFB reader) and `oletools` (independent MS-OVBA implementation); and the RTF parser against `oletools.rtfobj` (independent RTF OLE-object extractor). All are dev-only dependencies. The runtime parses untrusted input with the standard library alone.

The OLE/CFB parser (`engine/intake/ole.py`) is bounded in the same spirit: FAT and mini-FAT chains are followed with a visited set and a hop cap, directory entries are read up to a fixed ceiling, stream reads are capped, and MS-OVBA decompression stops and raises rather than allocating without limit. It never executes the compound file's contents; VBA macro streams are only decompressed to text for scanning, and `\x01Ole10Native` payloads are carved as data.

**A parser bug is not a traceback (D39).** Every one of those readers runs
in-process on bytes a sample controls, so `engine/guard.py` wraps every call: an
unexpected exception becomes that stage's named failure (`<stage>: unexpected
<Type>: <message>`) in `bundle.errors` — or in the delivery section's own
`errors` — the bundle is still written and sealed, and the traceback goes only
to the log. A documented parser error (`OleError`, `RtfError`) passes through
untouched rather than being flattened. A defect outside every guarded stage (a
pipeline driver or a renderer) exits **6** with one line and claims no bundle;
`1` stays INCONCLUSIVE and `2` stays mismatch/usage. `tests/hostile_corpus.py`
(29 fixtures, one lie each) and `tests/test_parser_properties.py` (hypothesis,
dev-only) are the gate, and `scripts/verify_setup.sh` submits three corpus
containers for real to prove the named/bounded/sealed contract end to end.

The RTF parser (`engine/intake/rtf.py`) is bounded the same way: the group scanner is a single pass with a group-depth cap (`MAX_GROUP_DEPTH = 1024`, because one small object per open group otherwise makes bytes-to-objects roughly 1:1) and an object-count cap, embedded objects are size-capped, and `\bin` raw regions are skipped so binary data cannot confuse group tracking — a `\bin` length that overruns the file or is negative raises instead of being silently dropped. A decoded `Package` object is an OLE compound file and is handed to the OLE parser; nothing is executed.

## Sample store (encryption at rest and retention)

`engine/store/` holds every accepted sample: content-addressed by plaintext SHA-256, encrypted at rest, and indexed. **Intake refuses before reading (D40):** `check_sample_source` runs on the `lstat` and refuses a symlink, a non-regular file (a FIFO blocks a read forever; a device can be endless) and anything above `DEFAULT_MAX_SAMPLE_BYTES` (256 MiB) — so no command allocates a sample in order to reject it. The same rule runs in the store's `put_file` and in `hatchery static`, which writes nothing and never touches the store; `submit --enqueue` and direct `submit` now agree about what a sample may be. The API uses the same number (D41): `MAX_UPLOAD_BYTES` equals `DEFAULT_MAX_SAMPLE_BYTES`, a test reads the Python source to keep them equal, and a larger multipart upload or `filePath` is refused with **413** before enqueueing. **An upload is never written to a file (D42).** The API streams the body into the store through `hatchery store put --stdin`, which reads under the same limit **while reading** — a pipe has no `lstat`, so that is the one guarantee a stream cannot offer — encrypts from memory, and returns the content address; the job is queued from that address. Nothing is staged, so a refusal stores nothing and leaves nothing behind, and `uploads/` is empty unless an operator submits a path from it. The intake is a **hostile-input surface** in both directions — the blobs are malware, and the key file is a credential.

- **Encryption.** AES-256-GCM in a versioned envelope whose header (magic, version, key id, nonce, plaintext length) is authenticated as additional data. Decryption authenticates first, then verifies the plaintext SHA-256 against the content address; a caller never sees bytes that are not the sample. Wrong key, tampered ciphertext/header, truncation and an unknown envelope version are distinct, fail-closed reasons. Blob size is bounded before it is read into memory, and an envelope that declares an implausible plaintext length is refused before allocation.
- **Writes.** Encrypt in memory → write a `0600` temporary (ciphertext) → `fsync` → atomic rename → `fsync` directory → index row. No write path produces a plaintext file, and an interrupted write cannot be mistaken for a sample (temporaries are `.tmp-` and are never indexed).
- **Key handling.** `HATCHERY_SAMPLE_KEY` or `HATCHERY_SAMPLE_KEY_FILE`. A key file must be a regular, non-symlink file with no group/other bits — a symlink, a device, a loose mode or a wrong length is refused, never followed. The key is never stored in the index, a bundle, a report, a log, argv or an error message; only a truncated SHA-256 key id is stored and printed. With no key configured the first write generates `<store>/.sample-key` (0600) and announces it; there is **no silent plaintext fallback**. Publication is atomic (D35): a complete `0600` temporary is linked into place, so a concurrent first writer can never read an empty key, and an empty legacy file makes the reader wait 2 s and then fail `key-invalid` instead of inventing one. Keep that file out of version control (`.gitignore` covers it) and, for a stronger posture, point `HATCHERY_SAMPLE_KEY_FILE` at a path outside the store — a key beside the ciphertext protects against plaintext at rest, not against a reader of the store directory.
- **Key ring and per-blob resolution (D29).** An explicit rotation creates `<store>/.sample-keyring`: a versioned, bounded (64 KiB, 32 keys) `0600` document with the active key and every retired key still needed. It is read with the same symlink/mode/length rules as a key file, and a version newer than this build understands is refused. Decryption resolves the envelope's key id **by id**; there is no trial decryption. A blob naming a key the ring does not hold is `unknown-key-id`, naming the key id and the blob, and is left untouched. A D28 single configured key keeps its `wrong-key` reason and a D28 store with no ring needs no migration.
- **Rotation and retirement.** `hatchery store key rotate` writes the ring **before** touching a blob, so a reader always has both keys; each blob is decrypted with the key its envelope names, authenticated, hash-checked against its content address, re-encrypted under the active key and written with the normal ciphertext-temp/`fsync`/rename/`fsync` path. Rotation takes the store lock (a second rotation reports `store-locked`), records per-blob failures without deleting or rewriting anything it cannot verify, and is resumable after a crash. It reports complete only when no blob references a retired key. `key retire` removes a retired key only when no blob header still names it; it is refused for the active key. No command prints key material.
- **Backup secrecy (D29).** `hatchery store backup` copies ciphertext blobs, the index and the queue using SQLite's backup API, hashes every file, and writes the manifest last. The key is **excluded by default**; `--include-key` is explicit, writes the ring `0600` inside the backup, warns loudly, and makes the manifest say a secret is present and whether the backup is restorable without the operator's key. The manifest contains key ids, never key material. Treat a backup made with `--include-key` exactly like the key itself: 0600, encrypted at rest ideally, never committed, never on a share. A backup without the key is not restorable on a clean host until the operator supplies the key, and the manifest says so.
- **Restore validation (D29).** A backup is hostile input. Restore validates the manifest version/schema/counts, every path (relative, no traversal, no symlink at any component), every size and hash, the SQLite `integrity_check`, the index-row/blob agreement, and every envelope version/key id/content address **before writing anything**. It authenticates each blob in memory; a corrupt blob, a newer schema or a traversal manifest writes nothing. A non-empty target is refused unless `--force`, and even then a blob whose bytes differ is never overwritten. After writing it verifies every entry and reports any key id that is not configured — it exits 2 rather than claiming success while anything is undecryptable. Index rows and queue job ids/states/attempts are preserved, not re-derived; a restored job whose sample is absent fails with that reason instead of running with no sample.
- **Reference safety.** Prune re-reads run bundles and the D27 queue at decision time and never deletes a referenced sample. A queued/running job whose sample cannot be identified makes `prune --apply` refuse. A malformed or oversized bundle is reported and protects nothing; that is why `store status` prints the scan warnings.
- **Concurrency and integrity.** Prune/migrate/verify take a non-blocking `flock`; writes are atomic; the index is a repairable cache of the blobs, not a second source of truth. `store verify` decrypts and hash-checks every entry and exits non-zero on any failure; `store migrate` never deletes a legacy blob it cannot verify.
- **What is not covered.** No KMS/HSM, escrow or split-key scheme; no multi-host rotation or cross-host backup; no scheduled rotation or key-expiry policy; no secure erase of a retired key's bytes; no disaster recovery for a destroyed key (if every copy is gone, its blobs are unrecoverable and `verify` says so); no signed backup manifest (an attacker who can rewrite the whole backup consistently can present a different one); no Windows ACL verification; and no encryption of the extracted delivery children or result bundles. Replay/submit use a single-use plaintext staging file for the path-based pipeline (0600, 0700 directory, unlinked on exit); SIGKILL can leave it in the OS temp directory. Result bundles under `results/` are still plaintext by design.

## Result bundles (integrity and retention, D33)

`results/<run>/` is evidence: attacker-controlled artifacts (extracted strings, delivery
children, pcaps, strace logs) plus the analysis document an analyst reads and hands to a
client. `manifest.json` at the run root makes "this bundle is intact" a checkable claim. It is
a **hash manifest, not a signature**, and the distinction is the whole point.

- **What it is.** SHA-256 and size for every file under the run root, plus provenance
  (format/version, run and task id, `created_at`, `stage`, `sealed_at`, the HATCHERY version,
  the sample's content address and store reference). It contains no sample bytes, extracted
  strings, IOCs, verdicts or counts: a manifest that restated findings would be a second
  source of truth (D4) and a second place to leak content to a client.
- **Written last, by one writer.** Temp + `fsync` + rename + directory `fsync`, `0600`,
  deterministic bytes (sorted paths, canonical JSON), so `sha256(manifest.json)` is
  reproducible. Every stage that mutates a run ends by re-sealing it — `submit`, `triage`,
  `push`, `replay` — because a manifest written only at submit time would report a
  legitimate triage as tamper, and a false break makes the control untrustworthy. A crash
  before the manifest leaves **no** manifest, never a half-manifested run reported complete.
  `triage` and `push` also verify the incoming state and refuse to modify a run that no
  longer matches its manifest, so a stage cannot launder an out-of-band edit.
- **Not signed, not MAC'd, deliberately.** The only key available to the process that writes
  a bundle is readable by any attacker who can write the bundle, so a MAC here would defend
  against a strictly weaker attacker than the one that matters; it would also duplicate
  D31's key-ring parser in Python or repurpose D29's sample key ring, whose retirement rules
  would silently un-verify every manifest the retired key signed. Half-built signing is
  worse than none.
- **The compensating control is an anchor.** `hatchery results seal <run>` prints the
  manifest SHA-256; record it when you deliver the run and check it with
  `hatchery results verify <run> --expect-manifest <sha256>`. A rewrite of an artifact *plus*
  its manifest is then `replaced`, and a deleted manifest is unambiguous
  (`manifest-missing`). **Without an anchor, an attacker who rewrites both is not detected.**
  That is the same limit D31 states for the chain head, in the same words.
- **Verification is hostile-input handling.** `verify` never follows a symlink (it is a
  `symlink` break, and the target is never read), refuses a manifest path that is absolute,
  contains `..`, a backslash or a NUL (`manifest-invalid`) instead of hashing outside the
  run, refuses a manifest version it does not understand, and bounds what it reads. `seal`
  refuses a run with more than 50 000 files or 4 GiB, a symlink anywhere, an unreadable file
  or no `bundle/analysis.json`, so it cannot become an unbounded operation.
- **`unsealed` is a state, not a pass.** A run with no manifest (written before this revision,
  or with its manifest deleted) reports `ok: false, state: "unsealed"` and exits 0 so an
  existing corpus keeps working. `--expect-manifest` makes a missing manifest a failure.
- **The claim includes nested units (D34).** A replay written inside a run
  (`results/<run>/replay-xxxx/`) is its own unit, but the parent's conclusion now includes
  whether that unit can be verified at all. A nested replay with no manifest makes the parent
  `ok: false, state: "broken", classification: "nested-unsealed"` with the nested directory as
  `path`, exit 1; a nested *broken* unit keeps its own classification and its prefixed path.
  A matching `--expect-manifest` can sit beside `ok: false` — the anchor proves the parent
  manifest, not the nested units, and the human output says so.
- **The corpus is sealable in one command.** `hatchery results seal <results-root> --all`
  seals every run under a root depth-first (nested units before their parent), is idempotent
  and resumable, reports `sealed`/`already`/`refused`/`ignored`, refuses a mismatching run and
  never follows a symlink. `--replace` is refused in batch: re-sealing mismatches across a
  corpus would bless tamper wherever it is found. Sealing a nested unit never changes the
  parent's manifest bytes, so a parent anchor recorded at delivery stays valid.
- **The recipient can check the claim.** `scripts/verify_manifest.py RUN
  [--expect-manifest SHA] [--json]` is standard library plus the same `verify_run`: no
  click/rich/YARA-X/capa/Docker, no database, no `HATCHERY_*` environment, the same
  classifications, states, JSON keys and exit codes. There is exactly one implementation of
  the rules, so the two outputs cannot drift.
- **Retention is off by default and operator-applied.** Nothing in `submit`, the worker or the
  API deletes a run directory; there is no timer. `hatchery results prune` is a dry run unless
  `--apply`, always keeps the newest `--keep-last` runs (minimum 1, `clamped: true` when the
  anchor decides), and **refuses the whole plan** when any run has no manifest, an invalid
  manifest, an unparseable bundle or an unsealed nested unit (`nested-unsealed`, distinct from
  `manifest-invalid`). Deletion renames to `<run>.deleting-<ts>` before removing
  the tree, so a crash leaves a stray the next prune completes rather than a half-deleted run
  a reader could trust. Two prunes serialise on a non-blocking `flock`; the second reports
  `results-locked`. Every prune appends a `0600` line to `results/.prune-log.jsonl` — an
  operator convenience, **not tamper-evident**, because the audit chain covers API actions,
  not local CLI maintenance (the same boundary D28/D29 have).
- **Reference safety is unchanged.** `store prune` still decides from a fresh scan of
  `<results>/<run>/bundle/analysis.json` and the queue. Pruning a run releases a sample only
  when nothing else references it; a sample still named by another run or a queued/running job
  stays protected. `store backup` still excludes `results/` and `store prune` still never
  deletes a bundle.
- **What is not covered.** The manifest is not signed and `results/` is **not encrypted at
  rest** — every reader is path-based and plaintext. A run on different (or network) storage
  was not exercised, nor is a run directory modified by an unrelated process while a prune
  runs (rename-then-remove mitigates; it does not prove). Windows ACLs are unverified, a root
  attacker who can rewrite the run, the manifest and every anchor copy is out of scope, clock
  skew moves the `--older-than` boundary, a manifest format change is refused rather than
  migrated, and a `bundle/` copied without its manifest verifies as `unsealed` — the honest
  answer, not a pass.

## API credentials and the audit record (D25/D30)

The API is loopback-bound by default and stores live malware. Its credential model
and its record of who did what are security controls in their own right, so both are
described here in the terms an auditor would use.

- **Two kinds of credential, one precedence.** `HATCHERY_ADMIN_TOKEN` and
  `HATCHERY_READ_TOKEN` (plus the back-compatible `HATCHERY_API_TOKEN`, which is an
  **admin** token) are the *bootstrap* pair. Stored tokens — `htk_<16 hex>_<secret>`,
  rows in the `api_tokens` table — are checked **after** them, so a stored token can
  never shadow a bootstrap credential and retiring every stored token cannot lock an
  operator out of a host they can already reach. A bootstrap token has no expiry and
  cannot be revoked through the API; that is what makes it the recovery path, and it
  is why removing it is an environment-and-restart action.
- **Only hashes are stored.** `api_tokens.secret_hash = sha256("hatchery/api-token/v1\0" + token)`.
  The raw token is generated by `npm run token -- create`, printed once to stdout,
  and never written to the database, a log, an error, a response or the audit log. A
  copy of the database does not yield a usable credential. Comparison is
  `crypto.timingSafeEqual` over the two 32-byte hashes.
- **An id is not a credential.** The token's id/prefix is printed in listings and
  audit rows and is not sufficient to authenticate: the id alone, the id plus a wrong
  secret, and a truncated token are all refused.
- **Checked per request.** revoked → expired → role, on every request, from the
  database (no in-memory cache to invalidate, no restart). Rotation is create → hand
  over → retire; the old token is refused on the next request, and a request already
  under way keeps the actor it resolved. A malformed row, a role this build does not
  understand and an unreadable token table all fail closed.
- **The refusal is generic; the record is precise.** Every refusal is the same
  `401 {"error":"Unauthorized"}` regardless of whether the token exists, expired or
  was revoked — the API must not become a token oracle. The audit row and the server
  log carry the exact reason (`token-malformed`, `token-unknown`,
  `token-hash-mismatch`, `token-revoked`, `token-expired`, `token-invalid-role`,
  `token-store-unreadable`) and the token id. The credential itself is never in
  either.
- **Lifecycle actions are audited.** `token.created`, `token.retired` and
  `token.expired` are rows in the same audit chain as requests. Listing, retirement and expiry are admin-only endpoints; **creation is CLI-only**, so a secret cannot
  be minted over the network or returned in a response. `npm run token -- list` shows
  id, role, prefix, name, timestamps and state — never the secret and never the hash.
- **Open mode is not authentication, and cannot re-open by accident.** With no
  bootstrap token and no stored token row the API is unauthenticated and says so at
  startup; actions are recorded as `authenticated: 0`. Creating a token closes it
  immediately; retiring the last token does **not** re-open it.
- **The audit log is a keyed hash chain.** Each new row carries `prev_hash` (the
  previous row's hash, or 64 zeros genesis), `entry_hash = sha256(canonical JSON array
  of [domain, id, prev_hash, actor, role, authenticated, method, path, status_code,
  action, detail, created_at])` — exactly the stored fields, no token, header, body or
  sample byte — and `entry_mac = HMAC-SHA256(key, "hatchery.audit.mac.v1" || key_id ||
  canonical)` from the local audit key ring (D31). The head read, the insert and the MAC
  share one `BEGIN IMMEDIATE` transaction, so two API processes or the API plus the CLI
  cannot fork the chain; the verifier is tested against two servers writing one database.
- **The audit key.** `HATCHERY_AUDIT_KEY` (64 hex) or `HATCHERY_AUDIT_KEY_FILE` (regular
  file, not a symlink, no group/other bits), else a generated `<db dir>/.audit-keyring`
  (`0600`, versioned, at most 64 KiB and 32 keys, key ids verified against their
  material). The ring is authoritative once it exists — a later env key that the ring
  does not hold is ignored and reported, because history verifies only with the keys it
  names. Rotation (`npm run audit -- key rotate`) adds a new active key and keeps the
  old ones, so no row is ever re-MAC'd; there is no retirement, because deleting a key
  would make the rows it authenticated unverifiable. Key material is never written to
  the database, a log, a response, a listing or a command line — only the derived id.
  An unreadable, loose, symlinked or newer-version ring, or a malformed env key,
  **stops the API from starting** rather than silently writing unkeyed rows.
- **The log is finite without being rewritten (D32).** `audit_log` never shrinks on its own: the serving process has no pruning path, no scheduled task and no background timer. `npm run audit -- compact --apply` archives the oldest segment — a `0600` JSONL file containing exactly the `audit_log` columns, plus a last-written `0600` manifest recording the window, counts, first/last id, tail `entry_hash`/`entry_mac`, key ids, archive SHA-256 and policy — and then deletes exactly that window in one `BEGIN IMMEDIATE` transaction that re-checks it. The live chain's first `prev_hash` equals the archived tail, so an offline verifier can splice the two; the `audit.compacted` row names the archive, the manifest hash and the tail. No row is re-hashed and no digest is recomputed: the archived rows keep the `entry_hash`/`entry_mac` they were written with, which is the difference between an archive and a forgery. `verify` reports the segments and the archive state; a missing, tampered or non-linking archive is a break with its own classification, and `assurance` still describes the live rows only, so `archive_verified` is a separate field (a verifier that did not read the archive says so). Growth is warned about and never enforced: `HATCHERY_AUDIT_WARN_ROWS` / `HATCHERY_AUDIT_WARN_BYTES` appear in `audit status`, the verify response and the startup banner, and a failed append is counted (persisted in `audit_chain_meta` best effort) — nothing is ever deleted to save space.
- **What the chain does and does not prove.** `GET /api/audit/verify` (admin-only,
  itself audited, bounded to 5 000 rows per call by default and 50 000 maximum)
  recomputes the chain and reports the first `forged` (digest consistent, MAC not — the
  row was rewritten without the key), `modified`, `deleted`, `inserted`, `unkeyed`
  (a keyed row followed by an unkeyed one), `unknown-key`, `truncated` or `replaced`
  (does not match an anchored head) row. It also reports `assurance`
  (`empty`/`unkeyed`/`mixed`/`keyed`), `coverage`, the key id/source (never material),
  the anchor and `append_failures_since_start`, because a bare `ok` overstates what was
  checked. **A deliberate truncation that also rewrites the stored head, or a restored
  older database, is internally consistent**: only a head recorded outside the database
  detects it, which is what `npm run audit -- head` + `verify --expect-head` are for.
  A root attacker who can read the key, rewrite the database and rewrite every backup
  consistently is out of scope; so is an append that failed before it was written (it is
  logged and counted, and the request is still answered — D25's rule). The log is
  readable by its owner, not encrypted at rest, and neither are its archives; an archive
  manifest is not signed, so an archive replaced wholesale together with its manifest is
  caught by the tail recorded in `audit_chain_meta`, not by the archive alone.
- **Pre-D30 history is honest about itself.** The migration is additive and does not
  backfill: older rows keep `NULL` hashes, the migration records the pre-chain
  boundary once, and the chain starts at the documented genesis anchor. `verify`
  reports those rows as `legacy`/`covered: false` and flags it when their count no
  longer matches the anchor. No retroactive tamper-evidence is claimed.
- **CORS is an allow-list.** The dashboard origin on `5173` (`localhost`,
  `127.0.0.1`, `[::1]`) plus comma-separated `HATCHERY_ALLOWED_ORIGINS`, matched
  exactly after normalisation. No wildcards, no substring or regex matches, no paths;
  an invalid entry is named and ignored at startup. An unlisted origin gets no
  `Access-Control-Allow-Origin` and no preflight grant, nothing is reflected,
  `Access-Control-Allow-Credentials` is never sent, and `Vary: Origin` always is. A
  request without an `Origin` header — curl, the worker, the CLI — is unaffected.
  **CORS is not authentication**: it restricts what a browser lets a page *read*, and
  an unlisted origin still reaches the API and still needs a token.

## Emulation (Windows PE)

`engine/emulate/` drives **Mandiant Speakeasy 2.0.0b6** (MIT, a pre-release kept in the optional `.[emulation]` extra, never in `dev` or the pinned python-gate matrix) to extract configuration from a Windows PE. It is a **declared, containerized, fail-closed analysis stage — not an isolation boundary** (D21).

- **What runs where.** Speakeasy interprets the sample's x86/x64 instructions in Unicorn and emulates Windows APIs in Python; the sample's code **never executes natively**. The residual attack surface is the host parser/emulator handling hostile bytes (pefile, Speakeasy's loader, capstone, Unicorn's C) — a superset of HATCHERY's existing host-side parsing surface (YARA-X, the delivery parsers). That is why it is not a library call on the analyst's desktop.
- **Container stance.** Emulation runs in its own image (`hatchery-emulation:latest`) at the probed isolation tier, with `--network none`, a read-only sample, `no-new-privileges`, **all capabilities dropped**, a non-root user (`uid 1000`), `mem_limit`/`nano_cpus`/`pids_limit` caps and a wall-clock cap. Sample and report move over the Docker API through a **named volume** read by a short `runc` sidecar — never a host bind mount (D5). At tier 2 the gVisor rootfs overlay is in-memory, so `get_archive` on the container itself cannot see the report; the named volume is the working route.
- **Gated on a boundary.** With no container runtime, emulation is **unavailable and declared**, not run on the host. The off-by-default `--allow-host-emulation` escape hatch exists for a dedicated Linux analysis host and prints a loud warning every time; it bypasses the container and is unsupported.
- **Fail-closed.** APIs the emulator does not implement (`error.type == "unsupported_api"`), emulator detection and the absent real network are declared blind spots. A crash, a wall-clock/timeout, or an empty report is **INCONCLUSIVE**, never clean. The report records the emulator version and a hash of the parsed report schema.
- **capa_dynamic.** Static capa and YARA over the emulator's captured memory snapshots, bounded by region/byte caps. It is **not** a synthesized CAPE report; a Speakeasy→CAPE adapter is deliberately not built.
- **Events.** Emulated events are written to a separate `emulation-events.jsonl`, never merged into the native `events.jsonl` (D4).

The emulation tests `importorskip` Speakeasy; the pinned python-gate matrix stays free of the beta. One opt-in CI job (`emulation-gate`) installs the extra and runs them.

## AI triage (local model)

`engine/triage/` asks a **local** Ollama model for an advisory triage of a run. It is the one component that handles sample-derived text outside a container, and it is treated as such (D22).

- **The sample stays on the machine — checked twice.** The endpoint defaults to `http://127.0.0.1:11434`; a non-loopback host is refused unless `--allow-remote-model`. Separately, a **`:cloud` model is refused** unless `--allow-remote-model` is set, because a cloud model is reached through localhost but runs on a vendor's GPU. Both permissions are recorded in the run and printed as a loud warning when used.
- **Hostile input is handled as hostile input.** All sample-derived text (filenames, strings, paths, URLs, mutex names, emulated IOCs) is rendered inside an `<untrusted-sample-data>` boundary. The boundary markers are stripped from the text first, so a sample cannot close the block early; control characters are removed and whitespace collapsed, so a string cannot forge extra lines. The prompt forbids following instructions inside the boundary. The adversarial-string test is in CI.
- **No sample text is executed, and none is stored in the triage result.** The result records the model-output summary, findings and the grounding ids; the raw evidence block is not persisted.
- **Fail-closed.** No model, a timeout, an unparseable response, or any verdict that fails grounding is `INCONCLUSIVE`, never clean.
- **Model output is never trusted as ground truth.** Ollama's schema enforcement is not the validator; `engine.triage.contract` re-validates, and `engine.triage.grounding` drops any claim whose citation does not exist in the run.

## Threat-intelligence push

`hatchery push` sends the run's STIX bundle to MISP or OpenCTI. The API token is read from `--token` or the environment, is used only to build the request, and is never written to the result object, the log, or the `push-<target>.json` audit file. TLS verification is on by default; `--insecure` exists for self-signed lab instances and warns each time it is used. A push is fail-closed: a non-2xx response or a transport error is reported with the status and exits non-zero.

## Hardening checklist for operators

- [ ] Run at tier 2 or 3 for anything untrusted. Verify with `hatchery doctor`.
- [ ] Keep the sandbox network `internal` (the default). It has no route off the host.
- [ ] Set `HATCHERY_ADMIN_TOKEN`. Without it the API is unauthenticated and says so at startup. Give integrations a `HATCHERY_READ_TOKEN` (viewer) instead of the admin token.
- [ ] Prefer stored tokens for anything long-lived: `cd server && npm run token -- create --role viewer --name "<integration>" --expires-in 90d`. The secret is printed once — put it in the client's secret store immediately, never in a file in the repository.
- [ ] Rotate by creating the replacement first, handing it over, then `npm run token -- retire <id>` (or `POST /api/tokens/:id/retire`). Check `npm run token -- list` afterwards: exactly one live token per client is the goal.
- [ ] Keep the bootstrap `HATCHERY_ADMIN_TOKEN` set even when stored admin tokens exist. It is the recovery path when a token is lost, expired or the token table is damaged.
- [ ] Treat the API's database (`HATCHERY_DB_PATH`, default `data/hatchery.db`) as a credential store: it holds the token hashes and the audit chain. Back it up and read-protect it like the sample-store key.
- [ ] Read the audit log (`GET /api/audit`) after an incident — it records who did what, without storing the credential itself — then run `GET /api/audit/verify` and confirm `ok: true`. A break names the row and whether it was modified, deleted, inserted, truncated or unhashed; a break in the middle means every row after it is suspect.
- [ ] Keep the audit key off the database directory if you can: point `HATCHERY_AUDIT_KEY_FILE` at a `0600` file (no symlink) outside the data directory, or set `HATCHERY_AUDIT_KEY` from your secret store. The generated key beside the database stops a database-only rewrite, not a reader of that directory.
- [ ] Rotate the audit key when you rotate credentials (`npm run audit -- key rotate`): old keys stay so history still verifies. Never delete a key by hand — a key that is gone takes the verifiability of every row it MAC'd with it.
- [ ] Record the chain head somewhere the database writer cannot rewrite (`npm run audit -- head` into your log collector or a ticket), and run `verify --expect-head <id>:<hash>` after a restore or a suspected incident. Without an anchor, a truncated tail plus a rewritten head verifies — that is the one limit keying does not remove.
- [ ] Read `assurance`, not just `ok`: `unkeyed` or `mixed` means part of the log is not authenticated (pre-D31 history), and `append_failures_since_start` above zero means an audit row was lost and logged instead of written.
- [ ] Watch audit growth (`npm run audit -- status`). Crossing `HATCHERY_AUDIT_WARN_ROWS` (default 500000) or `HATCHERY_AUDIT_WARN_BYTES` (default 256 MiB, database + WAL) is a warning in `audit status`, every verify response and the startup banner. **Nothing will ever be deleted for you** — compaction is an operator decision.
- [ ] Choose a retention policy deliberately — `--older-than 30d` for an obligation, `--max-rows N` for a disk budget — and run `npm run audit -- compact` **without** `--apply` first. `--apply` archives and deletes exactly the window the dry run printed. `--max-rows 0` is clamped to keep the newest chained row as the anchor.
- [ ] Compact when the API is running if you like: file I/O happens before the write lock, the window is re-checked inside it, and a concurrent append is never lost. A second compaction either completes an interrupted one or says there is nothing to do.
- [ ] Treat `<db dir>/audit-archives/` as evidence: `0600`, backed up, never committed, never edited. An edited archive is `archive-modified` (reported at the row, with the manifest hash mismatch named) and a rewritten one is `archive-mismatch`; deleting one is `archive-missing` and verification exits non-zero.
- [ ] Keep the audit key ring with the archives. Verify after a compaction (`npm run audit -- verify` reads the archives), and verify an archive offline on a machine without the database: `npm run audit -- verify --archive <file> --keyring <ring>`. Without the key the answer is `unknown-key`, never a pass.
- [ ] Read `assurance` and `archive_verified` together. `assurance` describes the live rows and must not drop because history was archived; `archive_verified: false` means the archives were **not** read (presence-only, a resumed page, or a break before them) and no claim is made about them.
- [ ] Copy an archive off the host before you expire it, and re-record the head (`npm run audit -- head`) after a compaction. Nothing in HATCHERY ships or deletes an archive, and an anchor older than the live segment is found in the archive only if the archive is read.
- [ ] Treat `data/hatchery.db` as a credential store and check its mode is `0600` (it is created that way; a copy or a restore may change it).
- [ ] List `HATCHERY_ALLOWED_ORIGINS` explicitly if you serve a dashboard from anywhere other than the documented `5173` origin. Do not try `*` — it is refused. CORS does not protect an API with no token; the token does.
- [ ] Keep `HATCHERY_HOST=127.0.0.1` unless you have a specific reason and a token set.
- [ ] Restrict `HATCHERY_ALLOWED_SAMPLE_ROOTS` to your real intake directory.
- [ ] Never point the API at a directory containing credentials or backups.
- [ ] Give the API's data directory the same care as the malware samples it stores: it holds live sample bytes and full behavioral traces.
- [ ] Back up the sample-store key (`HATCHERY_SAMPLE_KEY`/`HATCHERY_SAMPLE_KEY_FILE`, the generated `<store>/.sample-key`, or the `<store>/.sample-keyring` that rotation creates). Without it the stored samples cannot be decrypted — `hatchery store verify` will say `no-key`/`wrong-key`/`unknown-key-id`, and replay of a stored-only sample is INCONCLUSIVE. Never commit it.
- [ ] If a key is exposed, run `hatchery store key rotate`, confirm `store status` says `rotation_complete`, then `store key retire <old-key-id>`. Until retirement the old key still reads the pre-rotation copies; until rotation every retained sample is decryptable with the leaked key.
- [ ] Keep backups made with `--include-key` under the same protection as the key. A backup without the key cannot be restored on a clean host until you supply it; the manifest says which case you have.
- [ ] Rehearse a restore into a temporary root (`store restore BACKUP --target DIR`) and check it exits 0 and `store verify` passes before deleting the original. A restore that exits 2 has files but something is undecryptable or a job's sample is missing — read the report.
- [ ] Run `hatchery store status` and `hatchery store verify` before enabling a TTL. A pre-D28 store reports `legacy_plaintext` until `hatchery store migrate` encrypts it; a backup refuses that state rather than copying plaintext.
- [ ] Seal and verify a run before you deliver it: `hatchery results verify <run>` (`intact`), `hatchery results seal <run>` for anything written before D33, and record the printed manifest SHA-256 in the delivery note.
- [ ] Seal the corpus before pruning: `hatchery results seal <results-root> --all` (depth-first, idempotent, nested replays included). It refuses a mismatching run and refuses `--replace` in batch; a refusal means tamper, not a chore. Sealing a nested unit never changes the parent's manifest hash, so recorded anchors stay valid.
- [ ] Send the verifier with the run: `scripts/verify_manifest.py` needs Python 3 and nothing else. The recipient runs `python verify_manifest.py <run> --expect-manifest <sha256>`; it emits the same classifications and exit codes as `hatchery results verify` because it is the same code path.
- [ ] Anchor the delivery: the recipient (or you, later) checks `hatchery results verify <run> --expect-manifest <sha256>`. Without that anchor, an artifact rewritten together with its manifest verifies as intact — the manifest is a hash manifest, not a signature. A matching anchor with `ok: false` is possible: it proves the parent manifest, not the nested units.
- [ ] On receipt, verify before you read: a break names the classification (`modified`, `missing`, `extra`, `truncated`, `symlink`, `replaced`, `nested-unsealed`, …) and the path. `unsealed` means no manifest — copy the whole run directory, not just `bundle/`. `nested-unsealed` means the directory contains a replay unit nobody sealed: seal it before you trust the run.
- [ ] Treat `results/` as plaintext evidence: it holds attacker-controlled artifacts, extracted strings and full traces, and the manifest proves integrity, not confidentiality. Encrypt the volume if that matters, and never hand `bundle/` around without its manifest.
- [ ] Read `hatchery results status` before pruning. It reports `unsealed_runs`/`unsealed_nested` and says when a prune would be blocked. Growth is warned at `HATCHERY_RESULTS_WARN_RUNS` (2000) and `HATCHERY_RESULTS_WARN_BYTES` (10 GiB) and nothing is ever deleted for you.
- [ ] Prune deliberately: `hatchery results prune --older-than 30d --keep-last N` (dry run) first, read every reason, then `--apply`. `--apply` refuses the whole plan — and exits 2 — if any run has no manifest, an invalid manifest, an unparseable bundle or an unsealed nested unit (`nested-unsealed`); seal the corpus first (`hatchery results seal <results-root> --all`).
- [ ] Keep the anchor (`--keep-last`, minimum 1) and the sample store in mind: pruning a run releases a sample only when no other run or queued/running job references it. If two hosts hold bundles, point `--results` at both (or do not prune) — a reference on another machine is invisible.
- [ ] After a crash during a prune, run `hatchery results status` (it reports the `.deleting-` stray) and prune again: the next run completes the deletion.
- [ ] Cap resources: `ContainerConfig` sets `mem_limit`, `nano_cpus`, `pids_limit` and `no-new-privileges`. Do not remove them.
- [ ] Patch the host kernel regularly — at tier 1 the host kernel is the boundary.
- [ ] If you use triage, keep it local. Do not pass `--allow-remote-model` unless you intend sample-derived text to leave the machine.

## Security posture of the API

| Control | Default |
|:--|:--|
| Bind address | `127.0.0.1` |
| Authentication | off with a startup warning when nothing is configured; otherwise the bootstrap env pair (checked first, no expiry, cannot be revoked — the recovery path) plus stored tokens in `api_tokens` (hash only, id/role/prefix/expiry/revocation, checked per request) |
| Authorization | per-request role: reads need `viewer`, state changes need `admin`, `GET /api/audit`, `/api/audit/verify` and `/api/tokens` need `admin`. Tokens compared in constant time; creation is CLI-only (no create endpoint) |
| Token lifecycle | `npm run token -- create\|list\|retire\|expire` locally; `GET /api/tokens`, `POST /api/tokens/:id/retire` and `POST /api/tokens/:id/expire` for admins; rotation needs no restart; expiry and revocation checked per request; refusals are a generic 401 with the reason in the audit row only |
| Secrets in storage/logs | the raw token is never stored, printed twice, logged, audited or returned in a response; only `sha256(domain \|\| token)` and the id/prefix are persisted |
| Audit log | every answered request is recorded in `audit_log` (actor, role, authenticated, method, path minus query, status). No token, header, body or sample byte is stored. `GET /api/audit` is admin-only |
| Audit integrity | append-only **keyed** hash chain: `prev_hash`/`entry_hash` (SHA-256) plus `entry_mac`/`key_id` (HMAC-SHA-256 from the audit key ring), appended under `BEGIN IMMEDIATE`; recomputing the digests is not enough to forge a row. `GET /api/audit/verify` is admin-only, bounded, classifies the first break (`forged`/`modified`/`deleted`/`inserted`/`unkeyed`/`unknown-key`/`truncated`/`replaced`) and reports `assurance`/`coverage` — a bare `ok` is never the whole answer |
| Audit completeness | a truncation that rewrites the stored head, and a restored older database, are only detected against a head recorded elsewhere: `npm run audit -- head` → `verify --expect-head <id>:<hash>`. The anchor means "the head I recorded is still part of this log" (found in the live chain or a verified archive); `found_in`/`head_at_anchor` make staleness visible |
| Audit retention | **off by default**; applied only by `npm run audit -- compact --apply` (host-local, no timer, no server path). A compaction archives the oldest segment to a `0600` JSONL file plus a last-written `0600` manifest and hands the chain off; nothing is re-hashed and no row is ever rewritten. A crash at any step resumes; a concurrent compaction aborts having deleted nothing |
| Audit archives | operator state: `0600` in a `0700` directory, git-ignored, never on a share you do not control. The archive is a projection of `audit_log` — no token, header, body, sample byte or key material — and the manifest holds key **ids** only. Unencrypted and unsigned: an attacker who can rewrite an archive *and* its manifest consistently can present a different internally consistent one, which the tail hash in `audit_chain_meta` catches only against a live database you still trust |
| Audit growth | measured and warned, **never enforced**: `HATCHERY_AUDIT_WARN_ROWS` / `HATCHERY_AUDIT_WARN_BYTES` are reported by `audit status`, every verify response and the startup banner. Nothing is deleted to save space; a failed append is logged and counted (`append_failures_*`, persisted in `audit_chain_meta` best-effort) and the request is still answered |
| Audit key | `HATCHERY_AUDIT_KEY` / `HATCHERY_AUDIT_KEY_FILE` / generated `<db dir>/.audit-keyring` (0600, ≤64 KiB, ≤32 keys); the ring is authoritative once it exists; no retirement; an unusable key stops the API rather than downgrading the chain |
| Local state | the API database (token hashes + audit log) is `0600`, its `-wal`/`-shm` `0600`, and a data directory it creates `0700` |
| CORS | explicit allow-list: the dashboard origin on 5173 plus `HATCHERY_ALLOWED_ORIGINS` (exact match, no wildcard, no reflection, no credentials). Not authentication |
| Sample path submissions | restricted to `samples/` and `uploads/` |
| Uploaded sample | the body is streamed into the encrypted store (`hatchery store put --stdin`); the limit is applied **while reading** because a pipe has no `lstat`; nothing is written to a filesystem, so a refusal stores nothing and a truncated body is never queued. An upload that is stored and then abandoned before it is queued leaves a blob no job references — a prunable orphan, not a job pointing at nothing |
| Upload filenames | reduced to a bare name; traversal segments stripped |
| Artifact transfer | copy-based over the Docker API; tar members validated, `data` filter applied. At tier 2, a named Docker volume read by a short `runc` sidecar — never a host bind mount |
| Sample execution | unprivileged (`setpriv` to uid 1000); tracers run privileged, the sample never does |
| Sample at rest | content-addressed, AES-256-GCM envelope, `0600` blobs, atomic writes; key from env or a `0600` non-symlink file, else a generated local key that is announced; an optional `0600` key ring holds retired keys and is authoritative once rotation creates it |
| Sample backup | SQLite backup API for the index and queue, every blob hashed, manifest written last; the key is excluded unless `--include-key` (explicit, `0600`, loudly warned); restore validates paths/hashes/envelopes before writing |
| Sample retention | TTL explicit and off by default; `prune` dry-run unless `--apply`; referenced samples are never deleted; an unidentifiable queued job blocks the delete |
| Result bundles | `results/<run>/manifest.json`: deterministic SHA-256 per file, `0600`, written last by every stage that mutates the run (`submit`/`triage`/`push`/`replay`). `results verify` recomputes every hash and names the first break (`modified`/`missing`/`extra`/`truncated`/`symlink`/`manifest-invalid`/`manifest-version`/`manifest-missing`/`replaced`/`nested-unsealed`), reports `unsealed` as a distinct state and never `ok`, and never follows a symlink or a traversal path. A run directory's conclusion **includes its nested units**; `seal --all` closes a corpus depth-first and `scripts/verify_manifest.py` lets the recipient check it with the stdlib alone. **Unsigned and unMAC'd** — an artifact rewritten together with its manifest is caught only by `--expect-manifest`. **Not encrypted at rest** |
| Result retention | **Off by default**, applied only by `hatchery results prune --apply` (host-local, no timer, no server path). Never deletes a run it cannot verify — including one with an unsealed nested unit (`nested-unsealed`) — and the whole plan is refused with exit 2; always keeps the newest `--keep-last` (minimum 1, clamped); renames to `.deleting-<ts>` before removing (crash-resumable); serialises on a `flock`; appends a `0600` prune record that is **not** tamper-evident |
| Result growth | measured and warned, **never enforced**: `HATCHERY_RESULTS_WARN_RUNS` / `HATCHERY_RESULTS_WARN_BYTES` are reported by `results status`, along with `unsealed_runs`/`unsealed_nested` and whether a prune would be blocked; nothing is deleted to save space |

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
- The contents of `results/` and `data/`. They are attacker-controlled by design. The manifest makes a run verifiable and finite; it does not make its contents safe or confidential, and it is not a signature.
