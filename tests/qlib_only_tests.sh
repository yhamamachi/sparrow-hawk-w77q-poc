#!/bin/bash
# QLIB-only security tests (run on the board as root, after provisioning and a successful v1.1 install).
#   tests/qlib_only_tests.sh <tamper|badkey|rollback>
# Prints the section state before/after so "existing firmware remains valid" is visible.
set -u
cd "$(dirname "$0")/.."
A=${ASSETS:-build/assets}; T=./build/w77q_fwtool; SEC=${SEC:-4}
"$(dirname "$0")/../tools/w77q_bind.sh" bind
trap '"$(dirname "$0")/../tools/w77q_bind.sh" unbind' EXIT
echo "--- before:"; $T status $SEC | sed -n 1p
case "$1" in
  tamper)   $T install keys/good.key $A/tampered-v1.1.bin $A/tampered-v1.1.manifest $SEC; rc=$? ;;
  badkey)   $T install keys/bad.key  $A/badkey-v1.1.bin   $A/badkey-v1.1.manifest $SEC;   rc=$? ;;
  rollback) $T install keys/good.key $A/rollback-v1.0.bin $A/rollback-v1.0.manifest $SEC; rc=$? ;;
  *) echo "usage: $0 tamper|badkey|rollback"; exit 1;;
esac
echo "install exit code: $rc (10 = rejected by the flash)"
echo "--- after:";  $T status $SEC | sed -n '1p;3p'
exit $rc
