#!/bin/bash
# HATCHERY sandbox entrypoint — orchestrate sample execution with monitoring.
#
# Runs as root inside the container so the tracers can attach, then executes the
# sample as the unprivileged `user` account. The sample never runs as root.
#
# Artifact paths here are the contract with engine/sandbox/artifacts.py.
# If you change one, change ARTIFACT_SPECS in the same commit.
#
# Exit code is the sample's exit code, or 124 on timeout. It is never silently
# zeroed: the previous revision did `timeout ... || true; EXIT_CODE=$?`, which
# captured the status of `true` and reported every sample as exiting cleanly.

set -uo pipefail

SAMPLE="${1:-}"
TIMEOUT="${HATCHERY_TIMEOUT:-120}"
OUTPUT_DIR="/hatchery/output"

TCPDUMP_PID=""
INOTIFY_PID=""

log() { echo "[HATCHERY] $*"; }

if [ -z "$SAMPLE" ]; then
    log "ERROR: no sample path supplied"
    exit 2
fi

if [ ! -f "$SAMPLE" ]; then
    log "ERROR: sample not found: $SAMPLE"
    exit 2
fi

mkdir -p "$OUTPUT_DIR/strace" "$OUTPUT_DIR/tcpdump" "$OUTPUT_DIR/inotify" \
         "$OUTPUT_DIR/dropped" "$OUTPUT_DIR/filesystem" "$OUTPUT_DIR/exec"

log "Starting sandbox execution"
log "Sample: $SAMPLE"
log "Timeout: ${TIMEOUT}s"
log "Isolation tier reported by the engine: ${HATCHERY_TIER:-unknown}"
log "Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ---------------------------------------------------------------------------
# Background monitors
# ---------------------------------------------------------------------------

# Network capture. Root + NET_RAW (in Docker's default capability set).
if command -v tcpdump >/dev/null 2>&1; then
    log "Starting tcpdump on any interface"
    timeout "$((TIMEOUT + 10))" tcpdump -i any -w "$OUTPUT_DIR/tcpdump/capture.pcap" \
        -s 0 -n >/dev/null 2>&1 &
    TCPDUMP_PID=$!
else
    log "WARNING: tcpdump not available — no network capture"
fi

# Filesystem watch.
if command -v inotifywait >/dev/null 2>&1; then
    log "Starting inotifywait on home, tmp and shm"
    inotifywait -r -m -e create,modify,delete,move,attrib \
        --timefmt '%Y-%m-%dT%H:%M:%S' \
        --format '%T %w%f %e' \
        /home/user /tmp /dev/shm /var/tmp 2>/dev/null \
        > "$OUTPUT_DIR/inotify/inotify.log" &
    INOTIFY_PID=$!
else
    log "WARNING: inotifywait not available — no filesystem watch"
fi

# Filesystem snapshot. Exclude HATCHERY's own working directory and the kernel
# pseudo-filesystems: otherwise every artifact this script writes shows up in
# the diff and gets reported as a file the sample dropped.
SNAPSHOT_EXCLUDES=(-path /hatchery -prune -o -path /proc -prune -o -path /sys -prune -o)

snapshot_filesystem() {
    find / -xdev "${SNAPSHOT_EXCLUDES[@]}" -type f -print 2>/dev/null | sort
}

# Give the background monitors a moment to establish their watches. Without
# this the sample can finish before inotifywait is listening and the run reports
# "no filesystem events" for a sample that plainly touched the filesystem.
settle_monitors() {
    local waited=0
    while [ "$waited" -lt 30 ]; do
        if [ -n "$INOTIFY_PID" ] && ! kill -0 "$INOTIFY_PID" 2>/dev/null; then
            log "WARNING: inotifywait exited before the sample ran"
            return
        fi
        sleep 0.1
        waited=$((waited + 1))
    done
}

log "Waiting for monitors to become ready"
settle_monitors

# Pre-execution filesystem snapshot, used to identify dropped files.
log "Snapshotting filesystem before execution"
snapshot_filesystem > "$OUTPUT_DIR/filesystem/before.txt" || true

# ---------------------------------------------------------------------------
# Execute the sample under syscall tracing, as the unprivileged user
# ---------------------------------------------------------------------------

TRACE=()
if command -v strace >/dev/null 2>&1; then
    TRACE=(strace -f -tt -s 1024 -e trace=all -o "$OUTPUT_DIR/strace/strace.log")
    log "Executing sample under strace as user 'user'"
else
    log "WARNING: strace not available — no syscall log. Behaviour will be limited to"
    log "         filesystem events and network capture only."
fi

# setpriv drops privileges; the sample never runs as root.
EXIT_CODE=0
timeout "$TIMEOUT" "${TRACE[@]}" \
    setpriv --reuid=user --regid=user --clear-groups \
    "$SAMPLE" > "$OUTPUT_DIR/exec/exec.log" 2>&1 || EXIT_CODE=$?

log "Sample execution finished (exit: $EXIT_CODE)"

# ---------------------------------------------------------------------------
# Post-execution artifact capture
# ---------------------------------------------------------------------------

snapshot_filesystem > "$OUTPUT_DIR/filesystem/after.txt" || true

diff "$OUTPUT_DIR/filesystem/before.txt" "$OUTPUT_DIR/filesystem/after.txt" \
    2>/dev/null | grep '^>' | sed 's/^> //' > "$OUTPUT_DIR/dropped/new_files.txt" || true

# Keep the manifest but do not let it look like a dropped sample.
if [ -s "$OUTPUT_DIR/dropped/new_files.txt" ]; then
    log "Copying dropped files"
    while IFS= read -r dropped_file; do
        if [ -f "$dropped_file" ]; then
            dest="$OUTPUT_DIR/dropped/$(echo "$dropped_file" | tr '/' '_')"
            cp -f "$dropped_file" "$dest" 2>/dev/null || true
        fi
    done < "$OUTPUT_DIR/dropped/new_files.txt"
fi

# ---------------------------------------------------------------------------
# Stop monitors
# ---------------------------------------------------------------------------

if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
fi

if [ -n "$INOTIFY_PID" ]; then
    kill "$INOTIFY_PID" 2>/dev/null || true
    wait "$INOTIFY_PID" 2>/dev/null || true
fi

chown -R user:user "$OUTPUT_DIR" 2>/dev/null || true

# Be loud when monitoring produced nothing: an empty syscall log means the run
# is inconclusive, not that the sample was harmless.
if [ -s "$OUTPUT_DIR/strace/strace.log" ]; then
    log "Syscall log: $(wc -l < "$OUTPUT_DIR/strace/strace.log") lines"
else
    log "WARNING: no syscall log was produced — this run is INCONCLUSIVE, not clean"
fi

if [ -s "$OUTPUT_DIR/tcpdump/capture.pcap" ]; then
    log "Network capture: $(stat -c %s "$OUTPUT_DIR/tcpdump/capture.pcap") bytes"
else
    log "WARNING: no network capture was produced"
fi

if [ -s "$OUTPUT_DIR/inotify/inotify.log" ]; then
    log "Filesystem events: $(wc -l < "$OUTPUT_DIR/inotify/inotify.log") lines"
else
    log "WARNING: no filesystem events were recorded"
fi

log "End time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
exit "$EXIT_CODE"
