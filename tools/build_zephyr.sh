#!/bin/bash
# Build the version-printing Zephyr app for the Cortex-R52 of Sparrow Hawk (V4H).
#   ZEPHYR_BASE=<zephyr tree> ZEPHYR_SDK_INSTALL_DIR=<sdk> tools/build_zephyr.sh <out_dir> <ver> [<ver> ...]
# e.g. tools/build_zephyr.sh build/fw 1.0 1.1   ->  build/fw/zephyr-v1.0.bin, zephyr-v1.1.bin
# Requires `west` in PATH (activate the venv of your Zephyr workspace first).
set -euo pipefail
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(realpath -m "$1"); shift
BOARD=${BOARD:-sparrowhawk_rcar_v4h/r8a779g0/r52}
: "${ZEPHYR_BASE:?set ZEPHYR_BASE}"
mkdir -p "$OUT"
for v in "$@"; do
  west build -p always -b "$BOARD" -d "$OUT/_build-$v" "$HERE/zephyr/fw_version" -- -DFW_VERSION="$v"
  cp "$OUT/_build-$v/zephyr/zephyr.bin" "$OUT/zephyr-v$v.bin"
done
ls -l "$OUT"/zephyr-v*.bin
