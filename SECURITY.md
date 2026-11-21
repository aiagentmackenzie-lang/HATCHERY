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

The RTF parser (`engine/intake/rtf.py`) is bounded the same way: the group scanner is a single pass with a depth cap and an object-count cap, embedded objects are size-capped, and `\bin` raw regions are skipped so binary data cannot confuse group tracking — a `\bin` length that overruns the file or is negative raises instead of being silently dropped. A decoded `Package` object is an OLE compound file and is handed to the OLE parser; nothing is executed.

## Sample store (encryption at rest and retention)

`engine/store/` holds every accepted sample: content-addressed by plaintext SHA-256, encrypted at rest, and indexed. It is the one place a sample is copied to, and every entry point uses it (D28). It is a **hostile-input surface** in both directions — the blobs are malware, and the key file is a credential.

- **Encryption.** AES-256-GCM in a versioned envelope whose header (magic, version, key id, nonce, plaintext length) is authenticated as additional data. Decryption authenticates first, then verifies the plaintext SHA-256 against the content address; a caller never sees bytes that are not the sample. Wrong key, tampered ciphertext/header, truncation and an unknown envelope version are distinct, fail-closed reasons. Blob size is bounded before it is read into memory, and an envelope that declares an implausible plaintext length is refused before allocation.
- **Writes.** Encrypt in memory → write a `0600` temporary (ciphertext) → `fsync` → atomic rename → `fsync` directory → index row. No write path produces a plaintext file, and an interrupted write cannot be mistaken for a sample (temporaries are `.tmp-` and are never indexed).
- **Key handling.** `HATCHERY_SAMPLE_KEY` or `HATCHERY_SAMPLE_KEY_FILE`. A key file must be a regular, non-symlink file with no group/other bits — a symlink, a device, a loose mode or a wrong length is refused, never followed. The key is never stored in the index, a bundle, a report, a log, argv or an error message; only a truncated SHA-256 key id is stored and printed. With no key configured the first write generates `<store>/.sample-key` (0600, `O_EXCL`) and announces it; there is **no silent plaintext fallback**. Keep that file out of version control (`.gitignore` covers it) and, for a stronger posture, point `HATCHERY_SAMPLE_KEY_FILE` at a path outside the store — a key beside the ciphertext protects against plaintext at rest, not against a reader of the store directory.
- **Key ring and per-blob resolution (D29).** An explicit rotation creates `<store>/.sample-keyring`: a versioned, bounded (64 KiB, 32 keys) `0600` document with the active key and every retired key still needed. It is read with the same symlink/mode/length rules as a key file, and a version newer than this build understands is refused. Decryption resolves the envelope's key id **by id**; there is no trial decryption. A blob naming a key the ring does not hold is `unknown-key-id`, naming the key id and the blob, and is left untouched. A D28 single configured key keeps its `wrong-key` reason and a D28 store with no ring needs no migration.
- **Rotation and retirement.** `hatchery store key rotate` writes the ring **before** touching a blob, so a reader always has both keys; each blob is decrypted with the key its envelope names, authenticated, hash-checked against its content address, re-encrypted under the active key and written with the normal ciphertext-temp/`fsync`/rename/`fsync` path. Rotation takes the store lock (a second rotation reports `store-locked`), records per-blob failures without deleting or rewriting anything it cannot verify, and is resumable after a crash. It reports complete only when no blob references a retired key. `key retire` removes a retired key only when no blob header still names it; it is refused for the active key. No command prints key material.
- **Backup secrecy (D29).** `hatchery store backup` copies ciphertext blobs, the index and the queue using SQLite's backup API, hashes every file, and writes the manifest last. The key is **excluded by default**; `--include-key` is explicit, writes the ring `0600` inside the backup, warns loudly, and makes the manifest say a secret is present and whether the backup is restorable without the operator's key. The manifest contains key ids, never key material. Treat a backup made with `--include-key` exactly like the key itself: 0600, encrypted at rest ideally, never committed, never on a share. A backup without the key is not restorable on a clean host until the operator supplies the key, and the manifest says so.
- **Restore validation (D29).** A backup is hostile input. Restore validates the manifest version/schema/counts, every path (relative, no traversal, no symlink at any component), every size and hash, the SQLite `integrity_check`, the index-row/blob agreement, and every envelope version/key id/content address **before writing anything**. It authenticates each blob in memory; a corrupt blob, a newer schema or a traversal manifest writes nothing. A non-empty target is refused unless `--force`, and even then a blob whose bytes differ is never overwritten. After writing it verifies every entry and reports any key id that is not configured — it exits 2 rather than claiming success while anything is undecryptable. Index rows and queue job ids/states/attempts are preserved, not re-derived; a restored job whose sample is absent fails with that reason instead of running with no sample.
- **Reference safety.** Prune re-reads run bundles and the D27 queue at decision time and never deletes a referenced sample. A queued/running job whose sample cannot be identified makes `prune --apply` refuse. A malformed or oversized bundle is reported and protects nothing; that is why `store status` prints the scan warnings.
- **Concurrency and integrity.** Prune/migrate/verify take a non-blocking `flock`; writes are atomic; the index is a repairable cache of the blobs, not a second source of truth. `store verify` decrypts and hash-checks every entry and exits non-zero on any failure; `store migrate` never deletes a legacy blob it cannot verify.
- **What is not covered.** No KMS/HSM, escrow or split-key scheme; no multi-host rotation or cross-host backup; no scheduled rotation or key-expiry policy; no secure erase of a retired key's bytes; no disaster recovery for a destroyed key (if every copy is gone, its blobs are unrecoverable and `verify` says so); no signed backup manifest (an attacker who can rewrite the whole backup consistently can present a different one); no Windows ACL verification; and no encryption of the extracted delivery children or result bundles. Replay/submit use a single-use plaintext staging file for the path-based pipeline (0600, 0700 directory, unlinked on exit); SIGKILL can leave it in the OS temp directory. Result bundles under `results/` are still plaintext by design.

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
- [ ] Read the audit log (`GET /api/audit`) after an incident — it records who did what, without storing the credential itself.
- [ ] Keep `HATCHERY_HOST=127.0.0.1` unless you have a specific reason and a token set.
- [ ] Restrict `HATCHERY_ALLOWED_SAMPLE_ROOTS` to your real intake directory.
- [ ] Never point the API at a directory containing credentials or backups.
- [ ] Give the API's data directory the same care as the malware samples it stores: it holds live sample bytes and full behavioral traces.
- [ ] Back up the sample-store key (`HATCHERY_SAMPLE_KEY`/`HATCHERY_SAMPLE_KEY_FILE`, the generated `<store>/.sample-key`, or the `<store>/.sample-keyring` that rotation creates). Without it the stored samples cannot be decrypted — `hatchery store verify` will say `no-key`/`wrong-key`/`unknown-key-id`, and replay of a stored-only sample is INCONCLUSIVE. Never commit it.
- [ ] If a key is exposed, run `hatchery store key rotate`, confirm `store status` says `rotation_complete`, then `store key retire <old-key-id>`. Until retirement the old key still reads the pre-rotation copies; until rotation every retained sample is decryptable with the leaked key.
- [ ] Keep backups made with `--include-key` under the same protection as the key. A backup without the key cannot be restored on a clean host until you supply it; the manifest says which case you have.
- [ ] Rehearse a restore into a temporary root (`store restore BACKUP --target DIR`) and check it exits 0 and `store verify` passes before deleting the original. A restore that exits 2 has files but something is undecryptable or a job's sample is missing — read the report.
- [ ] Run `hatchery store status` and `hatchery store verify` before enabling a TTL. A pre-D28 store reports `legacy_plaintext` until `hatchery store migrate` encrypts it; a backup refuses that state rather than copying plaintext.
- [ ] Cap resources: `ContainerConfig` sets `mem_limit`, `nano_cpus`, `pids_limit` and `no-new-privileges`. Do not remove them.
- [ ] Patch the host kernel regularly — at tier 1 the host kernel is the boundary.
- [ ] If you use triage, keep it local. Do not pass `--allow-remote-model` unless you intend sample-derived text to leave the machine.

## Security posture of the API

| Control | Default |
|:--|:--|
| Bind address | `127.0.0.1` |
| Authentication | off, with a startup warning; set `HATCHERY_ADMIN_TOKEN` (full) and `HATCHERY_READ_TOKEN` (read-only). `HATCHERY_API_TOKEN` is still accepted as a back-compatible admin token |
| Authorization | per-request role: reads need `viewer`, state changes need `admin`, `GET /api/audit` needs `admin`. Tokens compared in constant time |
| Audit log | every answered request is recorded in `audit_log` (actor, role, authenticated, method, path minus query, status). No token, header, body or sample byte is stored. `GET /api/audit` is admin-only |
| CORS | permissive (`origin: true`) — tighten before exposing |
| Sample path submissions | restricted to `samples/` and `uploads/` |
| Upload filenames | reduced to a bare name; traversal segments stripped |
| Artifact transfer | copy-based over the Docker API; tar members validated, `data` filter applied. At tier 2, a named Docker volume read by a short `runc` sidecar — never a host bind mount |
| Sample execution | unprivileged (`setpriv` to uid 1000); tracers run privileged, the sample never does |
| Sample at rest | content-addressed, AES-256-GCM envelope, `0600` blobs, atomic writes; key from env or a `0600` non-symlink file, else a generated local key that is announced; an optional `0600` key ring holds retired keys and is authoritative once rotation creates it |
| Sample backup | SQLite backup API for the index and queue, every blob hashed, manifest written last; the key is excluded unless `--include-key` (explicit, `0600`, loudly warned); restore validates paths/hashes/envelopes before writing |
| Sample retention | TTL explicit and off by default; `prune` dry-run unless `--apply`; referenced samples are never deleted; an unidentifiable queued job blocks the delete |

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
- The contents of `results/` and `data/`. They are attacker-controlled by design.
