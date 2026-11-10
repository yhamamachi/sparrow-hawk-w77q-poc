#!/bin/bash
# Run one or more demo cases with SWUpdate on the board (as a normal user; sudo is used inside).
#
#   tools/demo.sh [-d <assets dir>] [-k <swu public cert>] <case> [<case> ...]
#
# cases:
#   v1.0       install the valid v1.0 package          -> expected: ACCEPTED (first install only)
#   v1.1       install the valid v1.1 package          -> expected: ACCEPTED (after v1.0)
#   tamper     package whose firmware byte was changed -> expected: REJECTED (integrity)
#   badkey     package installed with a wrong key      -> expected: REJECTED (authentication)
#   rollback   older, correctly produced v1.0          -> expected: REJECTED (rollback)
#   attacks    tamper, badkey, rollback in this order
#
# After each case the section version in the W77Q is printed, so you can see that a rejected
# update changed nothing. Then start the R52 from U-Boot (commands are printed at the end).
# The section to use is read from the package, nothing has to be given here.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
ASSETS=$HERE/build/assets
CERT=
while getopts "d:k:h" o; do
  case $o in
    d) ASSETS=$OPTARG ;;
    k) CERT=$OPTARG ;;
    *) sed -n '2,17p' "$0"; exit 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || { sed -n '2,17p' "$0"; exit 1; }
CERT=${CERT:-$ASSETS/keys/swu-sign.crt}

pkg() {
  case $1 in
    v1.0) echo valid-v1.0 ;; v1.1) echo valid-v1.1 ;; tamper) echo tampered-v1.1 ;;
    badkey) echo badkey-v1.1 ;; rollback) echo rollback-v1.0 ;; *) return 1 ;;
  esac
}
expect() { case $1 in v1.0|v1.1) echo ACCEPTED ;; *) echo REJECTED ;; esac; }

cases=()
for c in "$@"; do
  if [ "$c" = attacks ]; then cases+=(tamper badkey rollback)
  elif pkg "$c" >/dev/null; then cases+=("$c")
  else echo "unknown case: $c"; exit 1; fi
done

sudo "$HERE/tools/w77q_bind.sh" bind || exit 1
trap 'sudo "$HERE/tools/w77q_bind.sh" unbind' EXIT

section=; base=
for c in "${cases[@]}"; do
  f=$ASSETS/$(pkg "$c").swu
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
  section=$(cpio -i --to-stdout sw-description < "$f" 2>/dev/null | sed -n 's/.*section = "\([0-9]*\)".*/\1/p' | head -1)
  echo "=================================================================="
  echo "case: $c   package: $(basename "$f")   W77Q section: $section   expected: $(expect "$c")"
  echo "version before: $(sudo w77q_fwtool status "$section" | sed -n '1s/.*version=\([0-9]*\).*/\1/p')"
  if sudo swupdate -k "$CERT" -i "$f" > /tmp/demo_swupdate.log 2>&1; then result=ACCEPTED; else result=REJECTED; fi
  grep -E "w77q_fwtool|winbond|SWUPDATE (successful|failed)" /tmp/demo_swupdate.log | grep -v "failed \[1\]\|\*failed\*" | sed 's/^/  /'
  echo "result: $result"
  echo "version after:  $(sudo w77q_fwtool status "$section" | sed -n '1s/.*version=\([0-9]*\).*/\1/p')"
  base=$(sudo w77q_fwtool status "$section" | sed -n '1s/.*base=\(0x[0-9a-f]*\).*/\1/p')
  [ "$result" = "$(expect "$c")" ] || echo "!! unexpected result (expected $(expect "$c"))"
done

echo "=================================================================="
echo "Now start the R52. Reboot, stop autoboot, and type in the U-Boot console:"
echo "  sf probe"
echo "  sf read 0x40040000 $base 0x80000"
echo "  rproc init"
echo "  rproc load 0 0x40040000 0x200000"
echo "  rproc start 0"
echo "The Zephyr console (HSCIF1) prints: Zephyr Firmware Version x.y"
