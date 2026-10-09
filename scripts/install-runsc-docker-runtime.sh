#!/usr/bin/env bash
#
# Register gVisor (runsc) as a Docker runtime with HATCHERY's syscall trace on.
#
# WHY THIS EXISTS
#   HATCHERY's tier model promotes to tier 2 ("sandboxed-kernel") when a Docker
#   runtime named `runsc` (or `runsc-hatchery`) is present. The boundary is real
#   — gVisor answers the sample's syscalls in a userspace kernel — but the
#   collector has to change with it. `strace` inside a gVisor sandbox is not
#   relied upon (see docs/DECISIONS.md D2/D11): gVisor provides its own
#   Sentry-level syscall trace (`runsc --strace`), written to the host debug
#   log, which is what this script turns on.
#
#   gVisor added `debug`, `debug-to-user-log`, `strace`, `strace-syscalls`
#   and `strace-log-size` to its OCI-annotation override allow-list, so a
#   single analysis container can switch the trace on for itself. The log
#   destination (`--debug-log`) is a host-side runtimeArg and is NOT
#   annotation-overridable, which is why it is configured here — and only it.
#   HATCHERY sets the per-container annotations at tier 2 (see D14); this
#   script deliberately does not enable `--strace` globally, because that
#   would trace every container under the runtime.
#
# THIS IS AN OPERATOR ACTION
#   It requires root and restarts the Docker daemon. HATCHERY never runs it for
#   you. Run it yourself, on a host you are willing to lose, and only after
#   reading what a tier-2 run does and does not protect against (`hatchery
#   doctor`).
#
# USAGE
#   sudo ./scripts/install-runsc-docker-runtime.sh
#
# ENVIRONMENT
#   HATCHERY_RUNSC_RUNTIME   runtime name to register (default: runsc-hatchery)
#   HATCHERY_GVISOR_LOG_DIR  where runsc writes its debug/strace logs
#                            (default: /var/log/hatchery-gvisor)

set -euo pipefail

RUNTIME_NAME="${HATCHERY_RUNSC_RUNTIME:-runsc-hatchery}"
LOG_DIR="${HATCHERY_GVISOR_LOG_DIR:-/var/log/hatchery-gvisor}"
DAEMON_JSON="/etc/docker/daemon.json"

log()  { printf '[hatchery/runsc] %s\n' "$*"; }
fail() { printf '[hatchery/runsc] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || fail "gVisor runs on Linux only (found $(uname -s))."
[ "$(id -u)" -eq 0 ] || fail "must run as root (sudo)."

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|aarch64) : ;;
  *) fail "unsupported architecture: $ARCH (gVisor supports x86_64 and aarch64)." ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  fail "docker is not installed."
fi

log "runtime name:  $RUNTIME_NAME"
log "architecture:  $ARCH"
log "trace log dir: $LOG_DIR"

# ---------------------------------------------------------------------------
# Install runsc (apt repository preferred, tarball as a fallback)
# ---------------------------------------------------------------------------

if command -v runsc >/dev/null 2>&1; then
  log "runsc already installed: $(command -v runsc)"
else
  if command -v apt-get >/dev/null 2>&1; then
    log "installing runsc from the gVisor apt repository (preferred)"
    apt-get update -qq
    apt-get install -y -qq apt-transport-https ca-certificates curl gnupg >/dev/null
    curl -fsSL https://gvisor.dev/archive.key \
      | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
      > /etc/apt/sources.list.d/gvisor.list
    apt-get update -qq
    apt-get install -y -qq runsc
  else
    log "installing runsc from the release tarball"
    # Since 2026-07 a release is a tarball containing runsc plus a gvisor-bin/
    # directory of sidecars; runsc looks for that directory next to itself.
    URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    if command -v zstd >/dev/null 2>&1; then
      ( cd "$tmp" && curl -fsSLO "${URL}/gvisor.tar.zstd" && curl -fsSLO "${URL}/gvisor.tar.zstd.sha512" )
      ( cd "$tmp" && sha512sum -c gvisor.tar.zstd.sha512 )
      tar --zstd -xf "$tmp/gvisor.tar.zstd" -C /usr/local/bin
    else
      ( cd "$tmp" && curl -fsSLO "${URL}/gvisor.tar.bz2" )
      tar -xjf "$tmp/gvisor.tar.bz2" -C /usr/local/bin
    fi
    log "installed to /usr/local/bin/runsc"
  fi
fi

command -v runsc >/dev/null 2>&1 || fail "runsc still not found after install."
runsc --version || true

# ---------------------------------------------------------------------------
# Register the Docker runtime with the Sentry trace enabled
# ---------------------------------------------------------------------------

mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

if [ -f "$DAEMON_JSON" ]; then
  backup="${DAEMON_JSON}.hatchery-backup.$(date +%Y%m%d%H%M%S)"
  cp "$DAEMON_JSON" "$backup"
  log "backed up $DAEMON_JSON -> $backup"
fi

# `runsc install` merges a runtime entry into daemon.json. The flag after `--`
# is passed to every container launched with this runtime:
#   --debug-log=DIR/  one log file per sandbox in LOG_DIR (trailing slash)
# The per-container `strace`/`debug`/`debug-to-user-log`/`strace-log-size` flags
# are requested through OCI annotations by the engine, not here.
log "registering Docker runtime '$RUNTIME_NAME'"
runsc install --runtime "$RUNTIME_NAME" -- \
  --debug-log="${LOG_DIR}/"

# ---------------------------------------------------------------------------
# Restart Docker and smoke-test
# ---------------------------------------------------------------------------

log "restarting Docker"
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart docker
else
  fail "no systemctl: restart Docker yourself, then run: docker run --rm --runtime=$RUNTIME_NAME hello-world"
fi

log "smoke-testing the runtime"
if docker info --format '{{json .Runtimes}}' | grep -q "\"$RUNTIME_NAME\""; then
  log "runtime '$RUNTIME_NAME' is registered"
else
  fail "runtime '$RUNTIME_NAME' did not appear in docker info after restart"
fi

if docker run --rm --runtime="$RUNTIME_NAME" hello-world >/dev/null 2>&1; then
  log "smoke test passed: a container ran under $RUNTIME_NAME"
else
  log "WARNING: smoke test failed. Check $LOG_DIR for the .create log."
fi

cat <<EOF

Done. What to do next:
  1. cd into the HATCHERY repo and run:  hatchery doctor
     It should now report tier 2 (sandboxed-kernel) via runtime '$RUNTIME_NAME'.
  2. Detonate a probe. The run's collector line should name
     'gvisor-sentry-strace' and the bundle should contain events with
     source='gvisor-sentry'.

What to check by hand, because it cannot be automated here:
  * Does ${LOG_DIR} contain a .boot.txt with `strace.go:` lines for the run?
    HATCHERY finds it by the container ID it contains.
  * Docker's `get_archive`/`docker cp` cannot read files written inside a
    gVisor container (the rootfs overlay is in-memory), so the in-guest
    strace/inotify/pcap artifacts are not recoverable at tier 2. The Sentry
    trace is the collector for that reason; the bundle says so.
EOF
