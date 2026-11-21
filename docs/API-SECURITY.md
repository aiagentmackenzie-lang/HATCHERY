# API credentials, CORS and the audit chain (D30)

This is the operator's guide to Phase 4c. The decision record is
[`DECISIONS.md`](DECISIONS.md) D30; D8 remains authoritative for the API's
defaults and D25 for roles and the audit log's contents. The clean-copy
transcript is at the end of this page.

The phase exists because the API's own security record could not be trusted or
changed without downtime. D25 gave the API roles but left the credential as two
long-lived environment variables: a leaked token could only be replaced by editing
the environment and restarting, there was no expiry or revocation, the audit log was
a plain table that `sqlite3` could rewrite without evidence, and CORS was
`origin: true` — every origin reflected. Each of those is a case where an operator
believes something is protected when it is not.

## Two credentials, one precedence

| Credential | Where it lives | Expiry / revocation | Checked |
|:--|:--|:--|:--|
| `HATCHERY_ADMIN_TOKEN`, `HATCHERY_READ_TOKEN`, `HATCHERY_API_TOKEN` (admin) | environment | none — this is the **recovery path** | **first**, before any database read |
| stored tokens `htk_<16 hex id>_<43 char secret>` | `api_tokens` in the API's SQLite database, hash only | per request | after the bootstrap pair |

The bootstrap pair wins deliberately. A stored token can never shadow a bootstrap
credential (a row whose hash equals the bootstrap secret still authenticates as
bootstrap), and retiring every stored token cannot lock an operator out of a host
they can already reach. The cost is stated rather than hidden: a bootstrap token has
no expiry and cannot be revoked through the API — removing it is an
environment-and-restart action, which is exactly what a recovery credential is.

## Token lifecycle

```bash
cd server
npm run token -- create --role viewer --name "ci" --expires-in 30d   # secret printed ONCE
npm run token -- list                                               # id, role, prefix, state
npm run token -- retire htk_1a2b3c4d5e6f7a80 --reason "rotated"
npm run token -- expire htk_1a2b3c4d5e6f7a80 --in 0                 # expired now
```

`GET /api/tokens`, `POST /api/tokens/:id/retire` and `POST /api/tokens/:id/expire`
(`{"at": "<ISO-8601>"}` or `{"in_seconds": N}`) are the admin-only HTTP equivalents for
listing, revocation and expiry. None of them involves a secret, which is why they are
reachable over the API at all.

Every command accepts `--json` and `--db PATH`, and honours `HATCHERY_DB_PATH` (the
same resolution the server uses). Exit codes are stable: **0** success, **1** the
operation failed (unknown token id, database error), **2** usage error.

What is stored, and what is not:

- `secret_hash = sha256("hatchery/api-token/v1\0" + token)` — domain-separated,
  one-way, compared with `crypto.timingSafeEqual`.
- `id`/`prefix` — the token's first segment, printed in listings and audit rows. Not
  a credential: the id alone, the id plus a wrong secret, and a truncated token are
  all refused.
- The **raw token exists only in the `create` handover on stdout**, once. It is never
  written to the database, a log, an error, a response or the audit row. There is no
  create HTTP endpoint — `POST /api/tokens` is a 404 even for an admin — so a secret
  cannot be minted over the network.

Rotation:

1. `create` the replacement; copy the secret into the client's secret store.
2. Confirm the client works with it (`GET /api/tasks` with the new token).
3. `retire` the old one (CLI, or `POST /api/tokens/:id/retire` with an admin token).

Adding a token never invalidates another. Retirement takes effect on the **next
request** — the store is read per request, there is no cache to invalidate and no
restart — and a request already authenticated keeps the actor it resolved, so an
in-flight request completes. Verified end to end by retiring a token while a real
`POST /api/submit` was still running.

Expiry and revocation are evaluated in this order, every request: shape → id lookup
→ constant-time hash → revoked → expired → role. A revoked token stays revoked even
if its expiry is later moved.

## Open mode

With no bootstrap token **and no stored token row**, the API is unauthenticated and
warns at startup (twice, as D25 did). Actions are recorded with
`authenticated: 0` and the actor `anonymous` — they are never described as
authenticated. Creating a stored token closes the API immediately. Retiring the last
token does **not** re-open it: that would turn a routine credential change into a
security regression. Recovery is the bootstrap pair, or the CLI on the host.

## The refusal is generic, the record is precise

Every failure is `401 {"error":"Unauthorized"}` — the same bytes whether the token is
expired, revoked, or was never issued. The API is not a token oracle. The precision
lives where only an admin can read it: the audit row's `detail` and the server log
name the reason and the token id.

| Reason | Meaning |
|:--|:--|
| `no-credential` | nothing was presented (audit row only; not logged, to keep a port scan out of the log) |
| `token-malformed` | not our format, an id without a secret, a bad expiry timestamp |
| `token-unknown` | a well-formed id with no row |
| `token-hash-mismatch` | the id exists, the secret is wrong |
| `token-revoked` | `revoked_at` is set |
| `token-expired` | `expires_at` is in the past |
| `token-invalid-role` | the row's role is not `admin`/`viewer` (fail closed) |
| `token-store-unreadable` | the token table cannot be read (fail closed; never "open") |

## The audit chain

Every new row carries:

- `prev_hash` — the previous row's `entry_hash`, or `000…0` (64 zeros) for the first
  chained row;
- `entry_hash = sha256(canonical)` where `canonical` is
  `JSON.stringify(["hatchery.audit.v1", id, prev_hash, actor, role, authenticated,
  method, path, status_code, action, detail, created_at])`.

A JSON array is used so the encoding is unambiguous — every field is escaped, so a
path containing a delimiter cannot forge another row's encoding — and the field list
is exactly what the table already stores. **No token, header, body or sample byte is
an input.**

The head read and the insert are one `BEGIN IMMEDIATE` transaction (with a 5 s
`busy_timeout`), so two API processes — or the API and the token CLI — serialise
instead of forking. The test for this is cross-process: two servers, one database, a
40-request burst between them, one head and no two rows sharing a `prev_hash`.

Verification:

```bash
curl -s -H "Authorization: Bearer $ADMIN" 'http://127.0.0.1:3002/api/audit/verify?limit=5000' | jq .
# { "ok": true, "algorithm": "sha256(json-array-v1)", "genesis": "000…",
#   "rows_checked": 412, "complete": true, "next_after_id": null,
#   "first_broken": null,
#   "head": {"id": 412, "hash": "…", "matches_meta": true},
#   "legacy": {"rows": 0, "covered": false, "anchor_row_count": 0, "altered": false} }
```

`first_broken.classification` is causal, not cosmetic:

| Classification | How it is recognised |
|:--|:--|
| `modified` | the row links correctly but its `entry_hash` no longer matches its stored fields |
| `deleted` | a row links to a hash that is not the previous row's **and** the ids skip |
| `inserted` | a row links to a hash the chain never produced, with contiguous ids |
| `truncated` | the recomputed tail is not the recorded head (rows removed from the end) |
| `unhashed` | a row inside the chained region has no `entry_hash` |

The endpoint is bounded: 5 000 rows per call by default, 50 000 maximum, keyset
paging via `after`; an incomplete pass returns `next_after_id`. Verification is
itself an audited admin action.

### What the chain does not prove

The hash is unkeyed. There is no KMS, no HMAC key and no remote anchor, so an
attacker with write access who recomputes **every** hash from their edit onwards
*and* the recorded head produces a chain that verifies. The chain detects partial,
accidental and naive edits and makes consistent forgery a deliberate whole-log
rewrite; a root attacker who can rewrite the database and every backup consistently
is out of scope. An append that failed before it was written (disk full, a lock held
past the busy timeout) is logged and the request is still answered — D25's rule — and
leaves no row for the chain to see. If any of that matters, ship the log or its head
somewhere else (a syslog collector, a read-only copy).

### Pre-D30 rows

The migration is additive and does **not** backfill. Old rows keep `NULL` hashes;
the migration records `legacy_row_count`/`legacy_max_id` once; the first new row
links to the genesis constant. `verify` reports the legacy rows as
`legacy {rows, covered: false, anchor_row_count, altered}` — including when their
count no longer matches the anchor, because a deleted pre-chain row is worth
knowing about even though it was never tamper-evident.

## CORS

| Setting | Value |
|:--|:--|
| Default allow-list | `http://localhost:5173`, `http://127.0.0.1:5173`, `http://[::1]:5173` |
| Extend with | `HATCHERY_ALLOWED_ORIGINS=https://ops.example,https://report.example` |
| Matching | exact, after lower-casing and dropping a trailing slash; `scheme://host[:port]` only |
| Refused at startup (named in the log) | `*`, a path, a bare `host:port`, a non-http(s) scheme |
| Credentials | never (`Access-Control-Allow-Credentials` is not sent) |
| Non-browser clients | unaffected — no `Origin` header means no CORS header and no blocking |
| Preflight | granted only to an allow-listed origin, `max-age=600`, bounded methods/headers |

`HATCHERY_ALLOWED_ORIGINS` **adds** to the documented dashboard origin rather than
replacing it, so tightening the list cannot break the dashboard the README
documents. Nothing is reflected: an unlisted origin gets no
`Access-Control-Allow-Origin` and its preflight is not granted.

CORS is **not** authentication. It restricts what a browser lets a page *read*; an
unlisted origin still reaches the API and still gets the same 401 as anyone without a
token. Nothing in this repository claims otherwise.

## Operator checklist

- [ ] Keep the bootstrap `HATCHERY_ADMIN_TOKEN` set even when stored admin tokens
      exist — it is the recovery path.
- [ ] Create named tokens per client/role with an expiry; never share one token.
- [ ] Rotate by creating the replacement first, handing it over, then retiring.
      `npm run token -- list` should show one live token per client.
- [ ] Treat `HATCHERY_DB_PATH` (default `data/hatchery.db`) as a credential store:
      token hashes and the audit chain live there.
- [ ] Run `GET /api/audit/verify` after an incident and before relying on the log; a
      break names the row and the class. Everything after a break is suspect.
- [ ] List `HATCHERY_ALLOWED_ORIGINS` explicitly if you serve a dashboard from
      another origin. Do not try `*` — it is refused, not honoured.

## Captured transcript

Clean copy of the repository at the D30 code+tests commit `e374cb3`, with no
`.venv`, `node_modules`, `data/`, `results/`, `uploads/` or caches. The literal
protocol uses `python3.12`; the only deviation is that the interpreter uv had already
installed (`cpython-3.12.14`) was used directly, and `python -V` in the transcript
confirms 3.12.14. `scripts/verify_setup.sh` needs the interpreter's absolute path
because it changes directory internally. The documentation commit that follows does
not change the code under test.

```text
# HATCHERY Phase 4c — clean-copy verification transcript

Captured: 2026-11-21T11:20:37Z
Source:   git archive e374cb3 (D30 code+tests), unpacked into
          /tmp/hatchery-phase4c-clean; no .venv, node_modules, data/, results/,
          uploads/ or caches in the archive.

$ uname -srm; sw_vers -productVersion
Darwin 27.2.0 arm64
27.2.1
$ python -V; node -v; npm -v
Python 3.12.14
v26.13.0
12.2.2

$ python -m pytest -q
.......................                                                  [100%]
795 passed, 17 skipped, 3 xfailed in 21.17s

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

$ (cd server && npm ci && npm run typecheck && npm run build)
(no output: typecheck and build passed)

$ (cd server && npm test)
ℹ tests 69
ℹ pass 69
ℹ fail 0
ℹ skipped 0

$ (cd server && node --test test/queue_e2e.test.mjs test/queue_migration.test.mjs)
✔ a submission is queued, and a worker completes it into the API (1321.535875ms)
✔ a job that cannot produce a bundle is reflected as failed, not running (926.305667ms)
✔ a database created before the queue gains the queue_job_id column (480.271167ms)
ℹ tests 3
ℹ pass 3
ℹ fail 0

$ (cd dashboard && npm ci && npm run build)
dist/index.html                   0.64 kB │ gzip:  0.44 kB
dist/assets/index-81vfRC8U.css   15.69 kB │ gzip:  4.03 kB
dist/assets/index-CwBji8IX.js   272.30 kB │ gzip: 84.69 kB
✓ built in 507ms

$ PYTHON=/tmp/hatchery-phase4c-clean/.venv/bin/python scripts/verify_setup.sh
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
PASS  api/enqueue                        task 0482e23c-51d queued (no subprocess held open)
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

Repository state: scripts/verify_setup.sh's own data/repository-untouched check
passed, and every server/dashboard test used temporary databases and stores.
Nothing outside /tmp was written.
[transcript ends]
```

## What was not verified

- **Live rotation across multiple machines.** Rotation was exercised against one
  server and against two servers sharing one SQLite file. A deployment with separate
  token databases per host has no propagation mechanism (none is built).
- **Clock skew.** Expiry and revocation compare against the API host's clock. A
  client or a replica with a skewed clock is not compensated for, and the boundary is
  a string comparison after `Date.parse` — a token expiring "now" is refused from the
  next request.
- **An external secret manager / KMS.** None is integrated, and the audit chain is
  deliberately unkeyed, so keyed or externally anchored tamper evidence is not
  verified (it does not exist).
- **Browser-specific CORS behaviour.** The header behaviour (allowed, unlisted,
  preflight, `null` origin, no `Origin`) is tested over HTTP; a real
  Chrome/Firefox/Safari preflight matrix was not run, and no browser was used to
  confirm that a disallowed origin is actually blocked from reading a response.
- **Windows ACLs.** File permissions on the database were not verified on Windows;
  the POSIX `0600`-style posture is not asserted for NTFS.
- **A root attacker.** The chain is not protection against someone who can rewrite
  the database, `audit_chain_meta` and every backup consistently.
- **Audit appends that never happen.** A failed append is logged and the request is
  answered; the chain cannot detect a row that was never written.
