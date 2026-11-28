# Route

**This document is a route, not evidence.** Evidence — what a clean checkout can
actually do today — lives in [`BASELINE.md`](BASELINE.md). Product decisions
already taken live in [`DECISIONS.md`](DECISIONS.md). This page is the agreed
order of work, decided on **27 November 2026** with Raphael, starting from
`main` = `4276042` (D41, version 0.2.0, Python suite 963 passed / 17 skipped,
CI 9/9 green).

It exists because the queue had drifted into a list of adjectives — "signing,
encryption, KMS, off-host" — none of which said what to do on Monday. Every
slice below has a **gate** (the test that proves it) and a **stated caveat** (the
limit it does not remove). A slice that cannot name both does not belong here.

## The strategic call

HATCHERY's defensible asset is not feature coverage. Every competitor claims
evasion awareness, AI triage and STIX export. Almost none can hand a recipient
an artifact that verifies on a machine that never ran the tool.

So the route adds **no new analysis capability**. It makes the claim
**portable and third-party-verifiable**. Concretely, the end state is:

> A delivered run directory, plus a receipt, that a client verifies offline with
> Python and nothing else — and a report header that says exactly what the run
> could not see.

Decision numbers **D42–D48** are reserved for the slices below, in this order.

---

## D42 — The upload boundary is the store's boundary ✅ *delivered 27 Nov 2026*

**Now:** `server/src/routes/submit.ts` streams a request body of up to 256 MiB
into `uploads/<taskId>/` as a **plaintext** file; the worker then encrypts it
into the sample store and the staging copy is removed. D41 made the *refusal*
clean and the *limit* singular. It did not change what an **accepted** upload
looks like on disk.

**Why it matters:** this is the one place where the encryption-at-rest claim
(D28) is not true, at the exact moment the bytes are most dangerous — live
malware, at the largest size the system accepts. Every other byte in the system
is a `0600` AES-256-GCM envelope.

**Do:** stream the multipart body into the sample store's write path (the
encrypted envelope is produced incrementally) so no plaintext file at the size
limit exists at any point. If streaming the store is judged a larger slice than
one pass, the fallback is explicit and documented rather than silent: stage,
`unlink` immediately after the store write, and state the exposure window and
its byte bound in `SECURITY.md`. The fallback is a concession, not the goal.

**Delivered as:** `hatchery store put --stdin --json` (bytes → encrypted store,
limit applied *while reading*, nothing on a filesystem) then
`hatchery submit --from-store <sha> --enqueue --name <name>` (queue the address,
no path). The API no longer writes to `uploads/` at all. The slice also found and
fixed a defect D41 could not see: the multipart route **deadlocked above ~128 KiB**
because it consumed the file part after the loop, against busboy's backpressure —
96 KiB answered, 128 KiB never did, and the setup gate uploaded 13 bytes. A 40 MiB
upload is now `200` in 326 ms. See `DECISIONS.md` D42.

**Gate:** a real `submit` through the API leaves **no plaintext sample byte**
under `uploads/` at any instant — proven by a test that watches the directory
during an upload, not only after it — plus the existing D41 tests still green
(limit equality, 413 with no residue, second part refused).

**Delivered:** the stronger form — nothing is written there at all, so there is no
instant to watch. `tests/test_stream_intake.py` greps every file the test created
for the plaintext bytes and finds none; `server/test/upload_limit.test.mjs` asserts
`uploads/` is byte-for-byte unchanged after a real 2 KiB upload and that the task
row carries the address; `verify_setup.sh` `api/multipart-upload` and
`api/multipart-large` (2 MiB, above the old deadlock) both assert an empty
`uploads/`.

**Caveat to state:** the sample is held **in memory**, not streamed to ciphertext.
The v1 envelope authenticates the plaintext length in its AAD, so a writer must
know the size before it writes the header; a segmented v2 envelope (per-chunk
nonces, length taken from the ciphertext) is the fix and is its own slice with its
own migration. The 256 MiB cap is what keeps the cost a constant. Stated in
`DECISIONS.md` D42, `SECURITY.md` and `BASELINE.md`.

---

## D43 — Admission control: a credential is a budget ✅ *delivered 27 Nov 2026*

**Now:** `server/src/` has no rate limit, no per-token quota and no cap on
concurrent jobs. D41 stopped *residue* from refused requests. Nothing stops an
authenticated `admin` or `viewer` token filling the disk with **accepted**
256 MiB samples, or occupying every worker slot.

**Do:** per-token request rate, per-token accepted-bytes-per-window, a cap on
queued/running jobs per token, and `429` with `Retry-After`. Counters in the
existing SQLite database; refusals go into the audit chain with the token id
(D30), so a throttled caller is a recorded fact rather than a mystery.

**Gate:** a burst above each limit is refused with the documented status and
the audit chain carries the refusal; the counters survive a restart; the
existing 105 server tests unchanged.

**Caveat to state:** this is single-host, in-process accounting with a **fixed
window** (a burst across a window edge can pass ~2× the rate). It stops accident and
casual abuse, not a determined attacker holding a valid admin token — that attacker
already owns the tool's input path. Say so.

**Delivered as:** `admission_counters` in the API database, three per-caller limits
(60 requests / 10 min, 2 GiB accepted / 10 min, 8 queued+running jobs; `0` disables),
counted in the database so a restart does not forget them. A submission **reserves the
upload limit before the body is read** and settles to what was stored — the byte quota
runs ahead of the write, not after it. The job cap reads `jobs.owner` (queue schema 4)
rather than keeping a second tally. `429` with `Retry-After`, a body naming the limit,
and an audit row as `request.throttled`. A real restart test, and a second real API on
3003 in the setup gate. See `DECISIONS.md` D43; limits in `README.md`, posture in
`SECURITY.md`, transcript and seven gaps in `BASELINE.md`.

---

## D44 — A triage verdict names what the model saw (week 1)

**Now:** the triage section records `model` (a string), `base_url`,
`prompt_version`, `contract_hash`, `temperature: 0.0`, `seed: 0`,
`evidence_ids` and `evidence_chars`. That is better provenance than most
commercial products and it still has two holes.

**Do, three fields:**

1. `evidence_sha256` over the ordered evidence text actually sent. Two
   different evidence subsets of the same length are byte-identical today —
   `evidence_chars` is a count, not evidence.
2. `model_digest` from the local server (`/api/tags` or `/api/show` for the
   resolved model). If the server cannot prove one, record
   `model_digest: null` with `model_digest_unverified: "<reason>"` and mark the
   verdict **not reproducible**. A tag is a name; a digest is an artifact.
3. `claim_strength: "cited-not-proven"`. Grounding proves the model cited
   evidence that exists; it does not prove the citation is correct or the best
   association. That is in prose today (D22) — make it a field a consumer reads.

**Gate:** a swapped model (same tag, different weights) produces a different
`model_digest`; an evidence subset change produces a different
`evidence_sha256`; an unverifiable model produces `inconclusive` provenance, not
a silent pass; the existing adversarial-string CI guard still passes.

**Caveat to state:** a digest binds the artifact, not its honesty. A grounded
verdict from a poisoned model is still wrong, and it is now *verifiably* wrong
— which is the point.

---

## D45 — The results witness: the manifest is bound to a keyed, append-only record (weeks 2–3)

**The flagship.** `engine/results/manifest.py` refuses to MAC the manifest for
the right reason: the only key available to the writing process is readable by
an attacker who can already write the bundle, so a local MAC defends against a
strictly weaker attacker than the one that matters. The compensating control it
names — "record the hash when you deliver the run" — is a manual copy-paste into
`--expect-manifest` that no operator will actually perform, and it cannot
evidence a *deleted* run at all.

**Do:** `hatchery results witness <run>` appends
`{run_id, manifest_sha256, stage, produced_at, prev_hash, entry_mac}` to a `0600`
append-only log, HMAC'd from the same key-ring shape as D31, with D32's
compaction, archive manifest, crash-resume and growth-guard rules and D31's head
anchor. The verifier gains `witnessed: true|false` and four named breaks —
`witness-missing`, `witness-inserted`, `witness-truncated`, `witness-unkeyed` —
reported alongside the existing verdict rather than replacing it.
`scripts/verify_manifest.py` gains the same check so the recipient needs Python
and nothing else.

**Why this is the order-defining slice:** it converts "we hash our output" into
"we can prove, years later, that the report you hold is the one we produced, and
that no run was quietly removed from the set". Deletion evidence is the property;
rewrite evidence comes free with it.

**And it removes an owner gate.** The four "owner-gated" items in D41's closing
note read as blocked on a KMS. They are not. A keyed local witness carries most
of the property with no external trust root; KMS/off-host becomes an **upgrade
path**, not a precondition. Only *external* signers and *off-host* retention
still need a decision, and they become cheaper once the witness format exists.

**Gate:** a bundle rewritten together with its regenerated manifest is reported
as not-witnessed / mismatched; a deleted witness row is a named break; a
truncated tail is a named break; a two-writer burst loses no append; an offline
verify from a copy with no store succeeds; `results prune` and the witness do not
disagree about a run that exists.

**Caveat to state, in the doc and in the output:** a local witness is local. An
attacker who can read the witness key can forge the log; a root attacker is out
of scope, as everywhere else. The escalation path — WORM medium, off-host
witness, external signer — is named and costed, not implied.

---

## D46 — One observability contract per run, rendered as the header (week 4)

**Now:** what the run could not see is scattered across `bundle.errors`,
`summary.evasion_*`, coverage, `not_replayed`, emulation disposition, delivery
children not detonated, and triage `limitations`. Every consumer has to know to
look in five places, and a consumer who reads only `total_packets` or only
`ok: true` learns nothing.

**Do:** aggregate into one machine-readable `observability` block with a stable
vocabulary: collector and its blind spots, isolation tier, bytes examined vs
bytes parsed, events excluded and why, children not detonated, emulation
disposition, triage availability and reason. Render it as the **report header**,
not a footnote. The `results verify` output summarises it too.

**Gate:** no bundle is written without the block; a fixture per tier asserts the
named blind spots (tier 1 `strace` cannot see `RDTSC`/`CPUID`, tier 2 Sentry can
see `clock_gettime` and still cannot see `RDTSC`); a consumer that reads only the
block and the verdict reaches the same conclusion as one that reads the prose.

**Caveat to state:** the block reports what the **collector** could not see, not
what the **sample** did not do. Absence of a behaviour is not evidence of
absence of the behaviour.

---

## D47 — One honest quality number, with its denominator (week 4)

**Now:** 963 passing tests is *engineering* quality, and buyers read it as
*detection* quality. That gap is the portfolio's largest credibility liability.

**Do, three cheap and real things:**

1. **Per-detector negative controls** — every rule and detector run over the
   benign corpus, with an FP count and the corpus size published. `n=` always.
2. **Determinism** — k-run static reproducibility (replay already has the
   machinery) reported as a number, plus an explicit "dynamic and triage are not
   reproducible" line wherever a reproducibility claim appears.
3. **Coverage statement** — corpus size, what it contains, what it deliberately
   does not, and the resulting confidence interval.

**Do not** claim precision or recall until a labelled corpus is funded. "0.9
precision on 40 samples, interval wide, drawn from X" is honest and still
impressive. "Accurate" is the failure mode this project exists to avoid.

**Gate:** the scorecard reports counts with denominators; a zero-FP claim is
reproducible from `scripts/verify_fixtures.py`; the README's quality section
quotes only numbers that a gate produces.

---

## D48 — Bounded, seeded mutation over the hostile corpus (ongoing)

**Now:** `tests/hostile_corpus.py` holds 29 hand-built fixtures and
`tests/test_parser_properties.py` holds 12 hypothesis properties. Both find
defects you thought of.

**Do:** a bounded mutator over the corpus — N mutations or T seconds, whichever
first, **seed logged** so any failure replays — run as its own CI job with the
same "named, bounded, fast" assertion vocabulary. Budget it so it can never
become a flaky gate: a hang or a budget overrun fails rather than stalls.

**Why:** D39's 29 fixtures found five real defects in one sitting, including an
RTF group stack that `SECURITY.md` already claimed was capped. That is the ROI
of this slice, recurring.

**Gate:** the job fails on a new uncaught parser exception, not on a slow
runner; the seed and the mutation count are printed; a re-run with the recorded
seed reproduces the same corpus.

---

## Deliberately not on this route

Each refusal is a decision, not an omission. One line each in the log.

| Not doing | Why |
|---|---|
| **Shareable analysis URLs** (still in the roadmap text) | Turns a local tool into a multi-tenant web service: SSRF, IDOR, storage tenancy, viewer authn. Enormous new threat model, zero verifiable-truth gain. Remove it from the roadmap. |
| **KMS/HSM, escrow** | Deferred to an upgrade path after D45. Revisit only when a customer demands an external trust root. |
| **Encrypting `results/` at rest** | Defer, but add "bundles are plaintext by design; integrity is the manifest, confidentiality is not claimed" to the receipt so the limitation travels with the artifact. |
| **Dashboard ELF and emulation panels** | No customer asked. Rendering surface, not truth. |
| **STIX/OCSF mapping of PE/ELF structure** | An export-schema decision with no consumer. Revisit with D46 if a consumer appears. |
| **Windows guest, macOS dynamic analysis** | Procurement and licensing, not engineering. Keep the static-only statement loud. |
| **Cloud/remote detonation** | A procurement decision, not a slice. |
| **Per-account OIDC/SSO** | Single-operator tool. Named tokens with roles (D30) are the right scope until there are users. |

---

## Sequence

| When | Slice | Why here |
|---|---|---|
| Week 1 | **D42** ✅, **D43** ✅ | D42 closed the plaintext boundary and a 128 KiB deadlock on the same path; D43 bounded what a credential may spend |
| Week 1 | **D44** | Next. Small; every triage verdict becomes auditable before D45 puts it on the record |
| Weeks 2–3 | **D45** | The flagship. Needs the most care and the D32-shaped test set |
| Week 4 | **D46**, **D47** | Depend on D45: the quality claim should itself be witnessed |
| Ongoing | **D48** | Cheap insurance; runs itself in CI |

Version follows the slice as before (0.2.0 at D39; minor bumps on D42, D45).

## Definition of done for this route

A run directory that can be delivered and verified offline by someone with
Python and no HATCHERY, whose receipt names the run, its manifest, what the run
could not see, and — for the AI section — exactly which model artifact and which
evidence produced the verdict. Plus one quality number with its denominator.

## The one question this route does not answer

**Is HATCHERY a portfolio credential or a product?** Recorded here because it
changes what "done" means:

- **Credential** — D42–D44 plus D45, skip D47's corpus work, and lead every
  external conversation with the offline verifier. The demo ends with the client
  running a command and getting an answer they did not have to trust us for.
- **Product** — D47 becomes mandatory, and the remaining owner gates (off-host
  witness, external signer, multi-host stores, KMS/escrow) come back on the
  table, because tamper evidence has to survive the customer's own admin.

Raphael's call. The route above is correct under both, which is why it is the
route.
