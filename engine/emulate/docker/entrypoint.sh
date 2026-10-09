#!/bin/sh
# HATCHERY emulation entrypoint.
#
# Runs Mandiant Speakeasy with the argv the engine supplies (sample path, report
# path, config path, raw/arch flags) and writes the JSON report into
# /hatchery/output for copy-out over the Docker API. The engine never
# interpolates a sample name into a shell string — argv is passed intact.
#
# Exit status is preserved in emulation.exit so the manager can distinguish a
# clean run from a crash or an emulated-run timeout, and the log is kept so a
# failure is never silent.
set +e

mkdir -p /hatchery/output

speakeasy "$@" > /hatchery/output/emulation.log 2>&1
code=$?

echo "$code" > /hatchery/output/emulation.exit
exit "$code"
