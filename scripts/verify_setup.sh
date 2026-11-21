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
    echo "results $(find "$ROOT/results" -type f 2>/dev/null | wc -l | tr -d ' ')"
    echo "uploads $(find "$ROOT/uploads" -type f 2>/dev/null | wc -l | tr -d ' ')"
  } | shasum -a 256 | awk '{print $1}'
}
GUARD_BEFORE="$(guard_digest)"

echo "HATCHERY baseline verification"
echo "repo:   $ROOT"
echo "python: $($PY -V 2>&1) ($(command -v "$PY"))"
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
