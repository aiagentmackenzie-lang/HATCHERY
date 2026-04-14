#!/bin/bash
# HATCHERY sandbox entrypoint — orchestrate sample execution with monitoring
#
# This script runs inside the sandbox container. It:
# 1. Starts background monitors (tcpdump, inotifywait)
# 2. Executes the sample under strace supervision
# 3. Enforces a timeout
# 4. Captures all output artifacts

set -e

SAMPLE="$1"
TIMEOUT="${HATCHERY_TIMEOUT:-120}"
OUTPUT_DIR="/hatchery/output"

# Ensure output directories exist
mkdir -p "$OUTPUT_DIR/strace" "$OUTPUT_DIR/tcpdump" "$OUTPUT_DIR/inotify" \
         "$OUTPUT_DIR/dropped" "$OUTPUT_DIR/filesystem"

echo "[HATCHERY] Starting sandbox execution"
echo "[HATCHERY] Sample: $SAMPLE"
echo "[HATCHERY] Timeout: ${TIMEOUT}s"
echo "[HATCHERY] Time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# --- Start background monitors ---

# 1. Start tcpdump for network capture (need root for this)
if [ -w /hatchery/output/tcpdump ]; then
    echo "[HATCHERY] Starting tcpdump on any interface..."
    timeout "${TIMEOUT}" tcpdump -i any -w "$OUTPUT_DIR/tcpdump/capture.pcap" \
        -s 0 -n 2>/dev/null &
    TCPDUMP_PID=$!
fi

# 2. Start inotifywait to monitor filesystem changes
if command -v inotifywait &>/dev/null; then
    echo "[HATCHERY] Starting inotifywait on /home/user and /tmp..."
    inotifywait -r -m -e create,modify,delete,move,attrib \
        --timefmt '%Y-%m-%dT%H:%M:%S' \
        --format '%T %w%f %e' \
        /home/user /tmp /dev/shm /var/tmp 2>/dev/null \
        > "$OUTPUT_DIR/inotify/inotify.log" &
    INOTIFY_PID=$!
fi

# 3. Snapshot filesystem before execution
find / -xdev -type f 2>/dev/null | sort > "$OUTPUT_DIR/filesystem/before.txt" 2>/dev/null || true

# --- Execute the sample under strace ---

echo "[HATCHERY] Executing sample under strace..."

# Run strace with full syscall logging
# -f: follow child processes
# -tt: microsecond-precision timestamps
# -s 1024: capture up to 1024 bytes of string data per syscall
# -e trace=all: trace all syscalls
# -o: output to log file
if command -v strace &>/dev/null; then
    timeout "${TIMEOUT}" strace -f -tt -s 1024 -e trace=all \
        -o "$OUTPUT_DIR/strace/strace.log" \
        "$SAMPLE" 2>&1 || true
    EXIT_CODE=$?
else
    # Fallback: just run the sample without strace
    timeout "${TIMEOUT}" "$SAMPLE" 2>&1 || true
    EXIT_CODE=$?
fi

echo "[HATCHERY] Sample execution completed (exit: $EXIT_CODE)"

# --- Post-execution artifact capture ---

# Snapshot filesystem after execution
find / -xdev -type f 2>/dev/null | sort > "$OUTPUT_DIR/filesystem/after.txt" 2>/dev/null || true

# Find new/modified files (diff)
diff "$OUTPUT_DIR/filesystem/before.txt" "$OUTPUT_DIR/filesystem/after.txt" \
    2>/dev/null | grep "^>" | sed 's/^> //' > "$OUTPUT_DIR/dropped/new_files.txt" 2>/dev/null || true

# Copy dropped files
if [ -s "$OUTPUT_DIR/dropped/new_files.txt" ]; then
    echo "[HATCHERY] Copying dropped files..."
    while IFS= read -r dropped_file; do
        if [ -f "$dropped_file" ]; then
            dest="$OUTPUT_DIR/dropped/$(echo "$dropped_file" | tr '/' '_')"
            cp -f "$dropped_file" "$dest" 2>/dev/null || true
        fi
    done < "$OUTPUT_DIR/dropped/new_files.txt"
fi

# --- Stop background monitors ---

if [ -n "$TCPDUMP_PID" ]; then
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true
fi

if [ -n "$INOTIFY_PID" ]; then
    kill "$INOTIFY_PID" 2>/dev/null || true
    wait "$INOTIFY_PID" 2>/dev/null || true
fi

echo "[HATCHERY] Sandbox execution finished"
echo "[HATCHERY] End time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "[HATCHERY] Exit code: $EXIT_CODE"

exit $EXIT_CODE