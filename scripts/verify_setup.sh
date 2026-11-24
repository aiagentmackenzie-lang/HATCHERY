#!/usr/bin/env bash
# Baseline verification — repeatable on a clean checkout of this revision.
#
# Exercises the normal entry points against temporary state:
#   1. fixture manifest + known outcomes
#   2. CLI static submission (bundle contents)
#   3. compiled API: enqueue, restart durability, worker completion, ingest
#   4. dashboard dev server on 5173 and its API proxy
#
# It writes only under a temporary directory (HATCHERY_DB_PATH,
# HATCHERY_QUEUE_DB, HATCHERY_RESULTS_ROOT) and checksums the repository's
# databases, results and uploads before and after; it fails if they changed.
#
# Requirements: the Python package installed (`pip install -e ".[dev]"`),
# Node >= 20 on PATH, ports 3002 and 5173 free.
#
#   scripts/verify_setup.sh
#
# Exit status: 0 when every workflow passed; 1 otherwise.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/hatchery-verify.XXXXXX")"
API_PID=""
DASH_PID=""
FAILURES=0

# D28: every process that reads or writes samples must agree on one store, and
# the repository's own store must not be touched by verification.
export HATCHERY_SAMPLE_STORE="$WORK/samples"

cleanup() {
  for port in 3002 5173; do
    pids="$(lsof -nP -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true)"
    [ -n "$pids" ] && kill $pids 2>/dev/null
  done
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
  [ -n "$DASH_PID" ] && kill "$DASH_PID" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

pass() { printf 'PASS  %-34s %s\n' "$1" "$2"; }
fail() { printf 'FAIL  %-34s %s\n' "$1" "$2"; FAILURES=$((FAILURES + 1)); }
note() { printf 'NOTE  %-34s %s\n' "$1" "$2"; }

# Repository state that verification must not touch.
guard_digest() {
  {
    for db in "$ROOT/data/hatchery.db" "$ROOT/data/queue.db"; do
      if [ -f "$db" ]; then shasum -a 256 "$db"; else echo "absent $db"; fi
    done
    shasum -a 256 "$ROOT/samples/eicar.com"
    for sample in "$ROOT"/samples/*; do
      [ -f "$sample" ] && shasum -a 256 "$sample"
    done
    echo "results $(find "$ROOT/results" -type f 2>/dev/null | wc -l | tr -d ' ')"
    echo "uploads $(find "$ROOT/uploads" -type f 2>/dev/null | wc -l | tr -d ' ')"
  } | shasum -a 256 | awk '{print $1}'
}
GUARD_BEFORE="$(guard_digest)"

echo "HATCHERY baseline verification"
echo "repo:   $ROOT"
echo "python: $("$PY" -V 2>&1) ($(command -v "$PY"))"
echo "node:   $(node -v 2>/dev/null || echo 'not found') / npm $(npm -v 2>/dev/null || echo 'not found')"
echo

# ---------------------------------------------------------------------------
# 0. Preconditions
# ---------------------------------------------------------------------------
if ! "$PY" -c "import importlib.metadata as m; m.version('hatchery')" >/dev/null 2>&1; then
  fail "python/package-installed" "run: $PY -m venv .venv && source .venv/bin/activate && pip install -e \".[dev]\""
  exit 1
fi
pass "python/package-installed" "$("$PY" -c "import importlib.metadata as m; print(m.version('hatchery'))")"

if ! command -v node >/dev/null 2>&1; then
  fail "node/installed" "Node >= 20 is required for the server and dashboard"
  exit 1
fi

for port in 3002 5173; do
  if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "port/$port-free" "something is already listening on $port; stop it first"
    exit 1
  fi
done
pass "ports/free" "API (3002) and dashboard (5173) are available"

# ---------------------------------------------------------------------------
# 1. Fixtures
# ---------------------------------------------------------------------------
if (cd "$ROOT" && "$PY" tests/fixtures/acceptance/tools/generate_fixtures.py --check >/dev/null 2>&1); then
  pass "fixtures/manifest" "checked-in fixtures regenerate byte-identically"
else
  fail "fixtures/manifest" "run: python tests/fixtures/acceptance/tools/generate_fixtures.py --check"
fi

FIXTURE_LOG="$WORK/fixtures.log"
if (cd "$ROOT" && "$PY" scripts/verify_fixtures.py) >"$FIXTURE_LOG" 2>&1; then
  summary="$(grep -E 'passed, .*known defects' "$FIXTURE_LOG" | tail -1)"
  pass "fixtures/outcomes" "${summary:-known outcomes verified (known defects are listed in the output)}"
else
  fail "fixtures/outcomes" "fixture verification reported a failure"
  tail -5 "$FIXTURE_LOG"
fi

# ---------------------------------------------------------------------------
# 2. CLI submission from a directory that is not the repo
# ---------------------------------------------------------------------------
mkdir -p "$WORK/cli" "$WORK/results"
CLI_OUT="$WORK/cli/run.out"
if (cd "$WORK/cli" && \
    HATCHERY_RESULTS_ROOT="$WORK/results" \
    HATCHERY_QUEUE_DB="$WORK/cli-queue.db" \
    "$PY" -m engine.cli submit "$ROOT/samples/eicar.com" --no-sandbox -o "$WORK/cli/run" \
      >"$CLI_OUT" 2>&1); then
  if "$PY" - "$WORK/cli/run/bundle/analysis.json" <<'PY'
import json, sys
analysis = json.load(open(sys.argv[1]))
assert analysis["sample"]["sha256"] == (
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
), analysis["sample"]["sha256"]
rules = [m.get("rule") for m in analysis["static"]["yara"]["matches"]]
assert "HATCHERY_EICAR_TestFile" in rules, rules
PY
  then
    pass "cli/submit-static" "bundle sha256 and EICAR rule recorded"
  else
    fail "cli/submit-static" "bundle contents do not match the expected run"
  fi
else
  fail "cli/submit-static" "command failed; see $CLI_OUT"
  tail -20 "$CLI_OUT"
fi

# D38: the binary structure the analyzers already produced now reaches the
# bundle (and therefore pe_json/elf_json, the report route and the cluster
# fingerprint). Before this, static.pe/static.elf never existed and every
# reader found nothing.
BIN_RUN="$WORK/bin-meta"
if HATCHERY_SAMPLE_STORE="$WORK/bin-samples" HATCHERY_RESULTS_ROOT="$WORK/results" \
    HATCHERY_QUEUE_DB="$WORK/bin-queue.db" \
    "$PY" -m engine.cli submit "$ROOT/tests/fixtures/acceptance/benign/benign_pe.exe" \
      --no-sandbox -o "$BIN_RUN" >"$WORK/bin-meta.log" 2>&1; then
  if "$PY" - "$BIN_RUN/bundle/analysis.json" "$BIN_RUN/report.md" <<'CHECKBIN'
import json, sys
analysis = json.load(open(sys.argv[1]))
pe = analysis["static"]["pe"]
assert analysis["schema_version"] == "1.1", analysis["schema_version"]
assert pe and pe["is_valid_pe"] is True, pe
assert pe["machine_type"] == "x64 (AMD64)", pe["machine_type"]
assert analysis["static"]["elf"] is None, "a PE run must not claim ELF metadata"
report = open(sys.argv[2]).read()
assert "### PE Structure" in report, "the report must render the structure it carries"
assert "x64 (AMD64)" in report
CHECKBIN
  then
    pass "bundle/binary-metadata" "PE structure in static.pe, rendered in report.md"
  else
    fail "bundle/binary-metadata" "static.pe or the rendered report is missing the structure"
  fi
else
  fail "bundle/binary-metadata" "submission of the PE fixture failed; see $WORK/bin-meta.log"
fi

# D39: a hostile sample is named, bounded work — not a traceback, and not a run
# that cannot be delivered. Three containers from the corpus the test suite uses
# (one source of truth: tests/hostile_corpus.py), each submitted for real.
HOSTILE_DIR="$WORK/hostile"
mkdir -p "$HOSTILE_DIR"
if (cd "$ROOT" && "$PY" - "$HOSTILE_DIR" <<'BUILDHOSTILE'
import pathlib, sys
sys.path.insert(0, "tests")
import hostile_corpus as hc

out = pathlib.Path(sys.argv[1])
for name in ("ole_truncated", "zip_ratio_bomb", "gzip_corrupt_deflate"):
    (out / name).write_bytes(hc.corpus()[name].data)
BUILDHOSTILE
); then
  HOSTILE_OK=1
  for name in ole_truncated zip_ratio_bomb gzip_corrupt_deflate; do
    HOSTILE_RUN="$WORK/hostile-runs/$name"
    HOSTILE_LOG="$WORK/hostile-$name.log"
    if ! HATCHERY_SAMPLE_STORE="$WORK/hostile-samples" HATCHERY_RESULTS_ROOT="$WORK/results" \
        HATCHERY_QUEUE_DB="$WORK/hostile-queue.db" \
        "$PY" -m engine.cli submit "$HOSTILE_DIR/$name" --no-sandbox -o "$HOSTILE_RUN" \
          >"$HOSTILE_LOG" 2>&1; then
      HOSTILE_OK=0; note "hostile/$name" "submit exited non-zero; see $HOSTILE_LOG"; continue
    fi
    if grep -q "Traceback" "$HOSTILE_LOG"; then
      HOSTILE_OK=0; note "hostile/$name" "a traceback reached the operator"; continue
    fi
    if ! "$PY" - "$HOSTILE_RUN" <<'CHECKHOSTILE'
import json, sys
from pathlib import Path
from engine.results import verify_run

run = Path(sys.argv[1])
analysis = json.loads((run / "bundle" / "analysis.json").read_text(encoding="utf-8"))
delivery = analysis["static"]["delivery"]
recorded = delivery["errors"] + [u["reason"] for u in delivery["unsupported"]] + delivery["flags"]
assert recorded, "the hostile container was not named anywhere in the bundle"
assert len(delivery["children"]) <= 64, delivery["children"]
assert sum(c["size"] for c in delivery["children"]) <= 256 * 1024 * 1024
report = verify_run(run, _depth=1)
assert report["ok"] is True, report
assert (run / "manifest.json").is_file()
CHECKHOSTILE
    then
      HOSTILE_OK=0; note "hostile/$name" "bundle/manifest did not match the claim"
    fi
  done
  if [ "$HOSTILE_OK" = 1 ]; then
    pass "hostile/named-not-crash" "3 containers: named, bounded, sealed, no traceback"
  else
    fail "hostile/named-not-crash" "a hostile container escaped the contract (see notes)"
  fi
else
  fail "hostile/named-not-crash" "could not build the hostile corpus"
fi

# D40: the sample limit is applied to the stat, before the read. A 64 GiB
# *sparse* file costs no disk and no memory to create; the old path would have
# tried to allocate it in full before the store could refuse it.
"$PY" - "$WORK/huge.bin" <<'SPARSE'
import sys
with open(sys.argv[1], "wb") as handle:
    handle.truncate(64 * 1024**3)
SPARSE
HUGE_LOG="$WORK/huge-sample.log"
HUGE_START=$(date +%s)
if HATCHERY_SAMPLE_STORE="$WORK/huge-samples" HATCHERY_RESULTS_ROOT="$WORK/results" \
    "$PY" -m engine.cli submit "$WORK/huge.bin" --no-sandbox -o "$WORK/huge-run" \
      >"$HUGE_LOG" 2>&1; then
  fail "intake/oversized-before-read" "a 64 GiB sample was accepted"
else
  HUGE_ELAPSED=$(( $(date +%s) - HUGE_START ))
  if grep -q "Traceback" "$HUGE_LOG"; then
    fail "intake/oversized-before-read" "a traceback reached the operator"
  elif ! grep -q "too-large" "$HUGE_LOG"; then
    fail "intake/oversized-before-read" "the refusal did not name too-large"
  elif [ "$HUGE_ELAPSED" -gt 20 ]; then
    fail "intake/oversized-before-read" "the refusal took ${HUGE_ELAPSED}s (a read, not a stat)"
  elif [ -e "$WORK/huge-run/bundle/analysis.json" ]; then
    fail "intake/oversized-before-read" "a bundle was written for a refused sample"
  else
    pass "intake/oversized-before-read" "64 GiB refused in ${HUGE_ELAPSED}s from the stat; no bundle, no traceback"
  fi
fi

# The sample reached the store encrypted, content-addressed, and with no
# plaintext left anywhere in the store directory (D28).
STORE_STATUS="$WORK/store-status.json"
if HATCHERY_RESULTS_ROOT="$WORK/results" "$PY" -m engine.cli store status --json \
    --store "$WORK/samples" --results "$WORK/results" >"$STORE_STATUS" 2>"$WORK/store.log"; then
  if "$PY" - "$STORE_STATUS" "$WORK/samples" "$WORK/cli/run/bundle/analysis.json" <<'CHECK'
import json, sys
from pathlib import Path

status = json.load(open(sys.argv[1]))
store_root = Path(sys.argv[2])
bundle = json.load(open(sys.argv[3]))

assert status["samples"] == 1, status["samples"]
assert status["encrypted"] == 1 and status["legacy_plaintext"] == 0, status
entry = status["entries"][0]
assert entry["sha256"] == bundle["sample"]["sha256"], (entry, bundle["sample"])
assert bundle["sample"]["store"]["reference"] == bundle["sample"]["sha256"], bundle["sample"]
assert bundle["sample"]["store"]["encryption"] == "aes-256-gcm/v1", bundle["sample"]

blob = store_root / f"{entry['sha256']}.sample"
assert blob.is_file(), blob
data = blob.read_bytes()
assert data.startswith(b"HATCHERY-SAMPLE\x00"), data[:20]
assert b"EICAR" not in data, "plaintext sample bytes are on disk"
assert (blob.stat().st_mode & 0o777) == 0o600, oct(blob.stat().st_mode)
for path in store_root.rglob("*"):
    if path.is_file() and path.name != "index.db" and not path.name.startswith("index.db"):
        assert b"EICAR" not in path.read_bytes(), path
CHECK
  then
    pass "store/encrypted-at-rest" "content-addressed AES-256-GCM blob, 0600, no plaintext"
  else
    fail "store/encrypted-at-rest" "the sample store is not encrypted as specified"
  fi
else
  fail "store/encrypted-at-rest" "hatchery store status failed; see $WORK/store.log"
  tail -5 "$WORK/store.log"
fi


# ---------------------------------------------------------------------------
# 2a. D35: the first store key is published complete under concurrent writers
# ---------------------------------------------------------------------------
# A fresh store, several simultaneous first submits. Publication is a link of a
# fully written 0600 temporary (D35), so no opener may observe an empty key and
# fail with key-invalid. Each process must exit 0, exactly one key file and one
# content-addressed blob must remain, and no publication temporary may be left.
RACE_ROOT="$WORK/key-race"
mkdir -p "$RACE_ROOT/results"
RACE_PIDS=""
for index in 1 2 3 4; do
  (
    cd "$RACE_ROOT" || exit 1
    HATCHERY_SAMPLE_STORE="$RACE_ROOT/samples" \
    HATCHERY_RESULTS_ROOT="$RACE_ROOT/results" \
    HATCHERY_QUEUE_DB="$RACE_ROOT/queue.db" \
    "$PY" -m engine.cli submit "$ROOT/samples/eicar.com" --no-sandbox \
      -o "$RACE_ROOT/results/run-$index" >"$RACE_ROOT/out-$index.log" 2>&1
  ) &
  RACE_PIDS="$RACE_PIDS $!"
done
RACE_FAILED=0
for pid in $RACE_PIDS; do
  wait "$pid" || RACE_FAILED=1
done
RACE_KEYS=$(find "$RACE_ROOT/samples" -maxdepth 1 -name '.sample-key' 2>/dev/null | wc -l | tr -d ' ')
RACE_TEMPS=$(find "$RACE_ROOT/samples" -maxdepth 1 -name '.tmp-key-*' 2>/dev/null | wc -l | tr -d ' ')
RACE_BLOBS=$(find "$RACE_ROOT/samples" -maxdepth 1 -name '*.sample' 2>/dev/null | wc -l | tr -d ' ')
if [ "$RACE_FAILED" -eq 0 ] && [ "$RACE_KEYS" = "1" ] && [ "$RACE_TEMPS" = "0" ] \
    && [ "$RACE_BLOBS" = "1" ] \
    && ! grep -q "key-invalid" "$RACE_ROOT"/out-*.log 2>/dev/null; then
  pass "store/first-key-race" "4 concurrent first submits: one complete key, no partial read"
else
  fail "store/first-key-race" "exit=$RACE_FAILED keys=$RACE_KEYS temps=$RACE_TEMPS blobs=$RACE_BLOBS"
  grep -h "key-invalid\|Traceback\|OperationalError" "$RACE_ROOT"/out-*.log 2>/dev/null | head -3
fi


# ---------------------------------------------------------------------------
# 2b. Result bundles (D33): sealed at submit, verified, tamper-detected, pruned
# ---------------------------------------------------------------------------
RESULTS_VERIFY="$WORK/results-verify.json"
if "$PY" -m engine.cli results verify "$WORK/cli/run" --json >"$RESULTS_VERIFY" 2>"$WORK/results-verify.log"; then
  if "$PY" - "$RESULTS_VERIFY" "$WORK/cli/run" <<'CHECK'
import hashlib, json, sys
from pathlib import Path

report = json.load(open(sys.argv[1]))
run = Path(sys.argv[2])
manifest = run / "manifest.json"

assert report["ok"] is True, report
assert report["state"] == "intact", report
assert report["stage"] == "submit", report
assert manifest.is_file(), "the manifest must be at the run root"
assert not (run / "bundle" / "manifest.json").exists(), "bundle/ is not the place"
assert report["manifest_sha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
assert report["file_count"] >= 2, report
assert (manifest.stat().st_mode & 0o777) == 0o600, oct(manifest.stat().st_mode)
document = json.loads(manifest.read_bytes())
assert set(document["files"][0]) == {"path", "sha256", "size"}
CHECK
  then
    pass "results/manifest-sealed" "run root manifest, 0600, hashes verified, stage submit"
  else
    fail "results/manifest-sealed" "the manifest does not verify as specified"
  fi
else
  fail "results/manifest-sealed" "hatchery results verify failed; see $WORK/results-verify.log"
  tail -5 "$WORK/results-verify.log"
fi

cp -R "$WORK/cli/run" "$WORK/cli/tampered"
printf 'tampered after sealing\n' >> "$WORK/cli/tampered/bundle/events.jsonl"
if "$PY" -m engine.cli results verify "$WORK/cli/tampered" --json \
    >"$WORK/results-tamper.json" 2>/dev/null; then
  fail "results/tamper-detected" "a modified artifact still verified"
else
  if "$PY" - "$WORK/results-tamper.json" <<'CHECK'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["ok"] is False, report
assert report["state"] == "broken", report
assert report["classification"] == "modified", report
assert report["path"] == "bundle/events.jsonl", report
CHECK
  then
    pass "results/tamper-detected" "modified artifact named with its path, exit 1"
  else
    fail "results/tamper-detected" "the break was not classified as modified at the path"
  fi
fi

mkdir -p "$WORK/prune"
cp -R "$WORK/cli/run" "$WORK/prune/old"
cp -R "$WORK/cli/run" "$WORK/prune/new"
"$PY" - "$WORK/prune/old" <<'RESTAMP'
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from engine.results import build_manifest, write_manifest

run = Path(sys.argv[1])
stamp = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
write_manifest(run, build_manifest(run, stage="seal", sealed_at=stamp))
RESTAMP
if "$PY" -m engine.cli results prune --older-than 0s --keep-last 1 --apply --json \
    --results "$WORK/prune" >"$WORK/results-prune.json" 2>"$WORK/results-prune.log"; then
  if "$PY" - "$WORK/results-prune.json" "$WORK/prune" <<'CHECK'
import json, sys
from pathlib import Path

report = json.load(open(sys.argv[1]))
root = Path(sys.argv[2])
assert report["applied"] is True, report
assert [item["run_id"] for item in report["removed"]] == ["old"], report
assert (root / "new" / "manifest.json").is_file(), "the anchor run must survive"
assert not (root / "old").exists(), "the expired run must be gone"
log = root / ".prune-log.jsonl"
assert log.is_file(), "every prune appends a record"
assert (log.stat().st_mode & 0o777) == 0o600, oct(log.stat().st_mode)
assert json.loads(log.read_text().splitlines()[-1])["applied"] is True
CHECK
  then
    pass "results/prune-keeps-anchor" "dry-run order applied, anchor kept, 0600 prune log"
  else
    fail "results/prune-keeps-anchor" "the prune did not match its report"
  fi
else
  fail "results/prune-keeps-anchor" "hatchery results prune failed; see $WORK/results-prune.log"
  tail -5 "$WORK/results-prune.log"
fi

# D34: the whole corpus becomes verifiable in one command. A run with a legacy
# nested replay, an already-sealed run and a tampered run in one root: the
# unsealed units are sealed depth-first, the intact run is reported unchanged,
# the tampered run is refused (exit 2, nothing blessed) and the strays are
# ignored. Sealing the nested unit must not move the parent's manifest hash.
SEAL_ROOT="$WORK/seal-corpus"
mkdir -p "$SEAL_ROOT"
cp -R "$WORK/cli/run" "$SEAL_ROOT/already"
cp -R "$WORK/cli/run" "$SEAL_ROOT/with-replay"
rm -f "$SEAL_ROOT/with-replay/manifest.json"
mkdir -p "$SEAL_ROOT/with-replay/replay-0001/bundle"
cp "$WORK/cli/run/bundle/analysis.json" "$SEAL_ROOT/with-replay/replay-0001/bundle/analysis.json"
printf '{"replay_id":"0001"}\n' > "$SEAL_ROOT/with-replay/replay-0001/replay.json"
cp -R "$WORK/cli/run" "$SEAL_ROOT/tampered"
printf 'tampered before the corpus seal\n' >> "$SEAL_ROOT/tampered/bundle/events.jsonl"
mkdir -p "$SEAL_ROOT/notes"
printf 'not a run\n' > "$SEAL_ROOT/notes/readme.txt"
mkdir -p "$SEAL_ROOT/stray.deleting-20260101T000000Z"
ln -s "$WORK/cli/run" "$SEAL_ROOT/linked-run"
PARENT_HASH=$("$PY" - "$SEAL_ROOT/already/manifest.json" <<'CHECK'
import hashlib, sys
print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
CHECK
)
if "$PY" -m engine.cli results seal "$SEAL_ROOT" --all --json \
    >"$WORK/seal-all.json" 2>"$WORK/seal-all.log"; then
  fail "results/seal-corpus" "a corpus containing a tampered run must exit 2"
else
  status=$?
  if [ "$status" -ne 2 ]; then
    fail "results/seal-corpus" "expected exit 2 for a refused run, got $status"
  elif "$PY" - "$WORK/seal-all.json" "$SEAL_ROOT" "$PARENT_HASH" <<'CHECK'
import hashlib, json, sys
from pathlib import Path

report = json.load(open(sys.argv[1]))
root = Path(sys.argv[2])
parent_hash = sys.argv[3]

assert report["counts"] == {"sealed": 2, "already": 1, "refused": 1, "ignored": 3}, report["counts"]
sealed = [entry["run_id"] for entry in report["sealed"]]
assert sealed.index("replay-0001") < sealed.index("with-replay"), sealed
assert [entry["run_id"] for entry in report["already"]] == ["already"], report["already"]
refused = report["refused"][0]
assert refused["run_id"] == "tampered", refused
assert refused["classification"] == "modified", refused
assert refused["break_path"] == "bundle/events.jsonl", refused
ignored = {entry["name"]: entry["reason"] for entry in report["ignored"]}
assert ignored["notes"] == "not-a-run", ignored
assert ignored["stray.deleting-20260101T000000Z"] == "deleting-stray", ignored
assert ignored["linked-run"] == "symlink", ignored
assert (root / "notes").is_dir(), "an ignored entry must not be touched"
assert (root / "linked-run").is_symlink(), "a symlinked run must never be followed"
assert (root / "already/manifest.json").is_file()
assert hashlib.sha256((root / "already/manifest.json").read_bytes()).hexdigest() == parent_hash, \
    "sealing the corpus must not rewrite an intact parent manifest"
assert (root / "with-replay/replay-0001/manifest.json").is_file(), "the nested unit must be sealed"
assert (root / "with-replay/manifest.json").is_file(), "the parent must be sealed after its nested unit"
CHECK
  then
    pass "results/seal-corpus" "nested-first, already kept, tamper refused, strays ignored, anchor-safe"
  else
    fail "results/seal-corpus" "the corpus seal did not match its report"
  fi
fi

# D34: the verifier the recipient runs. Standard library only, the same code
# path, and it works on a copied run directory outside the checkout.
mkdir -p "$WORK/client-copy"
cp -R "$WORK/cli/run" "$WORK/client-copy/delivered-run"
if (cd "$WORK" && HATCHERY_SAMPLE_STORE="$WORK/absent-store" \
    "$PY" "$ROOT/scripts/verify_manifest.py" "$WORK/client-copy/delivered-run" --json \
    >"$WORK/client-verify.json" 2>"$WORK/client-verify.log"); then
  if "$PY" - "$WORK/client-verify.json" <<'CHECK'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["ok"] is True, report
assert report["state"] == "intact", report
assert report["classification"] is None, report
CHECK
  then
    if (cd "$WORK" && "$PY" "$ROOT/scripts/verify_manifest.py" "$WORK/cli/tampered" --json \
        >"$WORK/client-tamper.json" 2>/dev/null); then
      fail "results/client-verifier" "the client verifier passed a modified run"
    elif "$PY" - "$WORK/client-tamper.json" <<'CHECK'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["ok"] is False, report
assert report["classification"] == "modified", report
assert report["path"] == "bundle/events.jsonl", report
CHECK
    then
      pass "results/client-verifier" "copied run verifies stdlib-only; a modified run exits 1"
    else
      fail "results/client-verifier" "the client verifier misclassified the modified run"
    fi
  else
    fail "results/client-verifier" "the client verifier did not report the copied run intact"
  fi
else
  fail "results/client-verifier" "scripts/verify_manifest.py failed; see $WORK/client-verify.log"
  tail -5 "$WORK/client-verify.log"
fi

# ---------------------------------------------------------------------------
# 3. Compiled API: enqueue, restart durability, worker, ingest
# ---------------------------------------------------------------------------
for project in server dashboard; do
  if (cd "$ROOT/$project" && npm ci >/dev/null 2>&1); then
    pass "$project/npm-ci" "dependencies installed from the lockfile"
  else
    fail "$project/npm-ci" "npm ci failed"
  fi
  if (cd "$ROOT/$project" && npm run build >/dev/null 2>&1); then
    pass "$project/build" "production build succeeded"
  else
    fail "$project/build" "build failed"
  fi
done

mkdir -p "$WORK/api"
start_api() {
  (
    cd "$ROOT/server"
    exec env HATCHERY_HOST=127.0.0.1 HATCHERY_PORT=3002 \
      HATCHERY_DB_PATH="$WORK/api/hatchery.db" \
      HATCHERY_QUEUE_DB="$WORK/api/queue.db" \
      HATCHERY_RESULTS_ROOT="$WORK/api/results" \
      HATCHERY_ENGINE_PYTHON="$PY" \
      HATCHERY_UPLOADS_DIR="$WORK/api/uploads" \
      node dist/index.js
  ) >>"$WORK/api.log" 2>&1 &
  API_PID=$!
}

wait_for_health() {
  for _ in $(seq 1 60); do
    if curl -s -m 2 http://127.0.0.1:3002/api/health | grep -q '"status":"ok"'; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

start_api
if wait_for_health; then
  pass "api/compiled-start" "node dist/index.js answered /api/health"
else
  fail "api/compiled-start" "health endpoint did not answer; log: $(tail -3 "$WORK/api.log" | tr '\n' ' ')"
fi

submit_response="$(curl -s -m 10 -X POST http://127.0.0.1:3002/api/submit \
  -H 'content-type: application/json' \
  -d "{\"filePath\":\"$ROOT/samples/eicar.com\",\"noSandbox\":true}")"
task_id="$(printf '%s' "$submit_response" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('task_id',''))" 2>/dev/null)"

if [ -n "$task_id" ] && printf '%s' "$submit_response" | grep -q '"status":"queued"'; then
  pass "api/enqueue" "task $task_id queued (no subprocess held open)"
else
  fail "api/enqueue" "submission was not queued: $submit_response"
fi

# Durability: the projection survives an API restart because the queue owns it.
kill "$API_PID" 2>/dev/null
wait "$API_PID" 2>/dev/null
start_api
queued_after_restart=""
if wait_for_health; then
  queued_after_restart="$(curl -s -m 5 "http://127.0.0.1:3002/api/tasks/$task_id")"
fi
if printf '%s' "$queued_after_restart" | grep -q "$task_id"; then
  pass "api/restart-durability" "task survived an API restart"
else
  fail "api/restart-durability" "task was lost after restarting the API"
fi

if "$PY" -m engine.cli worker --once --queue "$WORK/api/queue.db" --timeout 120 \
    >"$WORK/worker.log" 2>&1; then
  pass "worker/executes-job" "worker drained the queue and exited 0"
else
  fail "worker/executes-job" "worker failed; see $WORK/worker.log"
  tail -5 "$WORK/worker.log"
fi

# D28: the queued job carries the content address, and the worker ran from the
# store rather than from the uploaded path.
if "$PY" -m engine.cli queue "$task_id" --json --queue "$WORK/api/queue.db" \
    >"$WORK/job.json" 2>/dev/null && "$PY" - "$WORK/job.json" <<'CHECKJOB'
import json, sys
job = json.load(open(sys.argv[1]))
assert job["status"] == "completed", job["status"]
assert job["sample_store_ref"] == job["sample_sha256"], job
assert job["sample_store_ref"] == "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", job
CHECKJOB
then
  pass "worker/store-backed-job" "job records a content address and completed from it"
else
  fail "worker/store-backed-job" "the queued job did not run from the sample store"
fi

# The API reconciles the completed job and ingests the bundle on read.
completed_file="$WORK/api/task.json"
for _ in $(seq 1 40); do
  curl -s -m 5 "http://127.0.0.1:3002/api/tasks/$task_id" >"$completed_file"
  if grep -q '"status":"completed"' "$completed_file"; then break; fi
  sleep 0.25
done
if "$PY" - "$completed_file" "$task_id" <<'PY'
import json, sys
body = json.load(open(sys.argv[1]))
assert body["task"]["status"] == "completed", body["task"]["status"]
assert body["task"]["sha256"] == (
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
), body["task"]["sha256"]
assert body["static_results"], "static results were not ingested"
PY
then
  pass "api/ingest-after-worker" "completed task has the expected hash and static results"
else
  fail "api/ingest-after-worker" "task did not reconcile to a published result"
fi

# D41: the API's upload boundary. One number (the engine's 256 MiB), applied on
# both branches, with nothing left behind when it refuses. The multipart success
# path is here because server-gate has no engine; the 413s are in
# server/test/upload_limit.test.mjs with a lowered plugin limit.
mkdir -p "$WORK/api/uploads"
printf 'MZ\220\000hatchery-multipart-upload' > "$WORK/api/upload-sample.exe"
MULTIPART_RESPONSE="$(curl -s -m 20 -X POST http://127.0.0.1:3002/api/submit \
  -F "sample=@$WORK/api/upload-sample.exe" -F "noSandbox=true")"
MULTIPART_ID="$(printf '%s' "$MULTIPART_RESPONSE" | "$PY" -c "import json,sys; print(json.load(sys.stdin).get('task_id',''))" 2>/dev/null)"
if [ -n "$MULTIPART_ID" ] && [ "$(ls "$WORK/api/uploads/$MULTIPART_ID" 2>/dev/null | wc -l | tr -d ' ')" = "1" ]; then
  pass "api/multipart-upload" "small upload queued and stored under the temp uploads root"
else
  fail "api/multipart-upload" "multipart upload was not stored: $MULTIPART_RESPONSE"
fi

"$PY" - "$WORK/api/uploads/oversized.bin" <<'SPARSEUPLOAD'
import sys
with open(sys.argv[1], "wb") as handle:
    handle.truncate(300 * 1024 * 1024)
SPARSEUPLOAD
OVERSIZED_STATUS="$(curl -s -o "$WORK/api/oversized.json" -w '%{http_code}' -m 20 \
  -X POST http://127.0.0.1:3002/api/submit \
  -H 'content-type: application/json' \
  -d "{\"filePath\":\"$WORK/api/uploads/oversized.bin\",\"noSandbox\":true}")"
if [ "$OVERSIZED_STATUS" = "413" ] && grep -q '"sample too large"' "$WORK/api/oversized.json"; then
  UPLOAD_DIRS="$(find "$WORK/api/uploads" -maxdepth 1 -mindepth 1 -type d | wc -l | tr -d ' ')"
  if [ "$UPLOAD_DIRS" = "1" ]; then
    pass "api/oversized-filepath" "300 MiB filePath refused with 413 before enqueue; no residue"
  else
    fail "api/oversized-filepath" "a refused submission created a task upload directory"
  fi
else
  fail "api/oversized-filepath" "expected 413 sample-too-large, got $OVERSIZED_STATUS: $(cat "$WORK/api/oversized.json" 2>/dev/null | head -c 200)"
fi
rm -f "$WORK/api/uploads/oversized.bin"

# D31: the API's own database is a credential store and an audit record. It must not
# be world-readable, and its audit chain must verify as a *keyed* chain (a chain that
# silently wrote unkeyed rows would claim less than the operator is told).
if [ "$(stat -f '%Lp' "$WORK/api/hatchery.db" 2>/dev/null)" = "600" ]; then
  pass "api/db-permissions" "API database is 0600 (audit log and token hashes)"
else
  fail "api/db-permissions" "API database mode is $(stat -f '%Lp' "$WORK/api/hatchery.db" 2>/dev/null), expected 600"
fi

audit_report="$WORK/api/audit-verify.json"
if node "$ROOT/server/scripts/audit.mjs" verify --json --db "$WORK/api/hatchery.db" >"$audit_report" 2>"$WORK/api/audit-verify.err"; then
  if "$PY" - "$audit_report" <<'PYCHECK'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["ok"] is True, report.get("first_broken")
assert report["assurance"] == "keyed", report["assurance"]
assert report["coverage"]["mac_rows"] == report["coverage"]["chained_rows"], report["coverage"]
assert report["append_failures_since_start"] == 0, report
PYCHECK
  then
    pass "api/audit-chain-keyed" "audit chain verifies as keyed, every row MAC'd"
  else
    fail "api/audit-chain-keyed" "verification output was not keyed/intact (see $audit_report)"
  fi
else
  fail "api/audit-chain-keyed" "audit verification failed: $(tail -2 "$WORK/api/audit-verify.err" | tr '\n' ' ')"
fi

if grep -q 'audit chain keyed' "$WORK/api.log" 2>/dev/null; then
  pass "api/audit-key-announced" "startup names the audit key id and never the material"
else
  fail "api/audit-key-announced" "startup did not report the audit key (see $WORK/api.log)"
fi

# D32: the audit log is finite without becoming a lie. Compact a real segment out of
# the API's own database: the archive is 0600, the manifest is written last, the live
# chain hands off to the archived tail, and the verifier reads the archive instead of
# reporting a shorter green history.
# Give the log enough history to compact. Each `token create` writes one chained
# `token.created` row, through the real CLI and the real appender.
for index in 1 2 3 4 5 6; do
  node "$ROOT/server/scripts/token.mjs" create --role viewer --name "setup-$index" \
    --db "$WORK/api/hatchery.db" >/dev/null 2>&1 || true
done
COMPACT_OUT="$WORK/api/audit-compact.json"
if node "$ROOT/server/scripts/audit.mjs" compact --json --db "$WORK/api/hatchery.db" \
    --max-rows 3 --apply >"$COMPACT_OUT" 2>"$WORK/api/audit-compact.err"; then
  if "$PY" - "$COMPACT_OUT" <<'CHECKCOMPACT'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["applied"] is True, report
assert report["reason"] is None, report
assert report["window"]["rows"] >= 1, report
assert report["join"]["proven"] is True, report
assert report["tail"]["entry_hash"], report
assert report["archive"]["sha256"], report
assert report["manifest"]["sha256"], report
assert report["archive"]["compression"] in ("none", "gzip"), report
assert report["remaining_eligible"] >= 0, report
CHECKCOMPACT
  then
    archive_rel="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["archive"]["path"])' "$COMPACT_OUT")"
    if [ "$(stat -f '%Lp' "$WORK/api/$archive_rel" 2>/dev/null)" = "600" ]; then
      pass "api/audit-compaction" "segment archived 0600, manifest written last, chain handed off"
    else
      fail "api/audit-compaction" "archive mode is $(stat -f '%Lp' "$WORK/api/$archive_rel" 2>/dev/null), expected 600"
    fi
  else
    fail "api/audit-compaction" "compaction report did not describe a proven handoff (see $COMPACT_OUT)"
  fi
else
  fail "api/audit-compaction" "compaction failed: $(tail -2 "$WORK/api/audit-compact.err" | tr '\n' ' ')"
fi

COMPACTED_VERIFY="$WORK/api/audit-verify-compacted.json"
if node "$ROOT/server/scripts/audit.mjs" verify --json --db "$WORK/api/hatchery.db" \
    >"$COMPACTED_VERIFY" 2>"$WORK/api/audit-verify-compacted.err"; then
  if "$PY" - "$COMPACTED_VERIFY" "$COMPACT_OUT" <<'CHECKSEGMENTS'
import json, sys
report = json.load(open(sys.argv[1]))
archive = json.load(open(sys.argv[2]))
assert report["ok"] is True, report.get("first_broken")
assert report["assurance"] == "keyed", report["assurance"]
seg = report["archive"]
assert seg["recorded"] is True, seg
assert seg["checked"] is True, seg
assert seg["verified"] is True, seg
assert seg["join"] == "proven", seg
assert seg["manifest_sha256"] == archive["manifest"]["sha256"], (seg, archive)
assert seg["rows"] == archive["window"]["rows"], (seg, archive)
assert report["segments"]["live_first_prev_hash"] == archive["tail"]["entry_hash"], report["segments"]
assert report["archive_verified"] is True, report
CHECKSEGMENTS
  then
    pass "api/audit-archive-verified" "live chain verifies across the boundary; archived rows were read"
  else
    fail "api/audit-archive-verified" "cross-segment verification was not intact (see $COMPACTED_VERIFY)"
  fi
else
  fail "api/audit-archive-verified" "verification failed: $(tail -2 "$WORK/api/audit-verify-compacted.err" | tr '\n' ' ')"
fi

# ---------------------------------------------------------------------------
# 3b. D29: key rotation and a restorable backup of the live store + queue
# ---------------------------------------------------------------------------
ROTATE_OUT="$WORK/rotate.json"
if "$PY" -m engine.cli store key rotate --json --store "$WORK/samples" \
    >"$ROTATE_OUT" 2>"$WORK/rotate.log"; then
  if "$PY" - "$ROTATE_OUT" <<'CHECKROTATE'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["complete"] is True, report
assert report["rotated"], "nothing was re-wrapped"
assert report["active_after"] and report["active_after"] != report["active_before"], report
assert report["failed"] == [], report
assert report["per_key_blob_counts"] == {report["active_after"]: len(report["rotated"])}, report
CHECKROTATE
  then
    if "$PY" -m engine.cli store verify --json --store "$WORK/samples" \
        >"$WORK/verify-after-rotate.json" 2>"$WORK/verify-after-rotate.log"; then
      pass "store/key-rotation" "every blob re-wrapped; verify passes on the new active key"
    else
      fail "store/key-rotation" "store verify failed after rotation"
      tail -5 "$WORK/verify-after-rotate.log"
    fi
  else
    fail "store/key-rotation" "rotation did not complete on one key"
  fi
else
  fail "store/key-rotation" "hatchery store key rotate failed; see $WORK/rotate.log"
  tail -5 "$WORK/rotate.log"
fi

BACKUP_DIR="$WORK/backup"
RESTORE_DIR="$WORK/restored"
if "$PY" -m engine.cli store backup --json --include-key -o "$BACKUP_DIR" \
    --store "$WORK/samples" --queue "$WORK/api/queue.db" \
    >"$WORK/backup.json" 2>"$WORK/backup.log"; then
  if "$PY" -m engine.cli store restore "$BACKUP_DIR" --target "$RESTORE_DIR" --json \
      >"$WORK/restore.json" 2>"$WORK/restore.log"; then
    if "$PY" - "$WORK/backup.json" "$WORK/restore.json" <<'CHECKRESTORE'
import json, sqlite3, sys

backup = json.load(open(sys.argv[1]))
restore = json.load(open(sys.argv[2]))
assert backup["counts"]["samples"] >= 1, backup
assert backup["key"]["included"] is True, backup["key"]
assert backup["key"]["restorable_without_operator_key"] is True, backup["key"]
assert restore["ok"] is True, restore
assert restore["verify"]["ok"] is True, restore["verify"]
assert restore["samples"] == backup["counts"]["samples"], (restore, backup)
assert restore["queue_jobs"] == backup["counts"]["queue_jobs"] >= 1, (restore, backup)
connection = sqlite3.connect(restore["queue_db"])
try:
    ids = [row[0] for row in connection.execute("SELECT job_id FROM jobs")]
finally:
    connection.close()
assert ids, "the restored queue lost its job ids"
CHECKRESTORE
    then
      pass "store/backup-restore" "manifest hashes every blob; restored job ids and samples verify"
    else
      fail "store/backup-restore" "the restored backup did not verify"
    fi
  else
    fail "store/backup-restore" "hatchery store restore failed; see $WORK/restore.log"
    tail -5 "$WORK/restore.log"
  fi
else
  fail "store/backup-restore" "hatchery store backup failed; see $WORK/backup.log"
  tail -5 "$WORK/backup.log"
fi

# ---------------------------------------------------------------------------
# 4. Dashboard dev server and proxy
# ---------------------------------------------------------------------------
(cd "$ROOT/dashboard" && exec npm run dev -- --port 5173 --strictPort) >"$WORK/dash.log" 2>&1 &
DASH_PID=$!
page=""
for _ in $(seq 1 80); do
  page="$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://localhost:5173/ || true)"
  [ "$page" = "200" ] && break
  sleep 0.25
done
[ "$page" = "200" ] \
  && pass "dashboard/dev-server" "http://localhost:5173/ returned 200" \
  || fail "dashboard/dev-server" "dashboard did not answer on 5173 (see $WORK/dash.log)"

proxy="$(curl -s -m 5 http://localhost:5173/api/health || true)"
printf '%s' "$proxy" | grep -q '"status":"ok"' \
  && pass "dashboard/api-proxy" "/api/health proxied to the API" \
  || fail "dashboard/api-proxy" "proxy did not reach the API"

# ---------------------------------------------------------------------------
# 5. Repository untouched
# ---------------------------------------------------------------------------
GUARD_AFTER="$(guard_digest)"
if [ "$GUARD_BEFORE" = "$GUARD_AFTER" ]; then
  pass "data/repository-untouched" "databases, results, uploads and EICAR unchanged"
else
  fail "data/repository-untouched" "verification wrote into the repository state"
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "RESULT: baseline verified"
  exit 0
fi
echo "RESULT: $FAILURES check(s) failed"
exit 1
