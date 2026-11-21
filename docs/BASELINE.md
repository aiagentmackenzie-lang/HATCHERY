# Baseline verification

Verified **21 November 2026** on top of revision `34565f7` (Phase 4b: the key
ring, rotation and recoverable backups, D29). The D28 store baseline was
`be9386d`, whose clean-copy transcript is in
[`RETENTION.md`](RETENTION.md#captured-transcript); the D29 transcript is in
[`BACKUP.md`](BACKUP.md#captured-transcript). The detector scorecard is
unchanged from `4b48490`.

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
  dashboard, and passes the full Python suite: **795 passed, 17 skipped,
  3 xfailed** (was 771/17/3 at `be9386d`; 24 tests cover key rotation,
  retirement, backup and restore). `ruff` is clean and `mypy engine/` reports
  no issues in 83 source files.
- `tests/fixtures/acceptance/` holds deterministic inputs (checked in, generated
  from byte templates, no compiler or download) with a manifest of SHA-256 and
  expected outcomes. `--check` fails if either the bytes or the expectations
  drift.
- The fixture scorecard is **13 passed, 0 failed, 3 known defects**. It
  distinguishes a genuine match (EICAR), a completed scan with zero findings
  (negative text with rules loaded), and a detector that could not run (capa
  unavailable, with its exit code and stderr preserved).
- `scripts/verify_setup.sh` exercises the normal entry points against temporary
  state: **21 passed, 0 failed** (was 19/0).
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
key/retention semantics have their own suites and CI jobs. This baseline is
about installation, packaging, normal entry points and static acceptance inputs;
it does not re-certify those features. The store's storage/retention guarantees
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
```

Expected: `795 passed, 17 skipped, 3 xfailed`; the fixture scorecard
`13 passed, 0 failed, 3 known defects`; the setup check `21 passed, 0 failed`.

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
