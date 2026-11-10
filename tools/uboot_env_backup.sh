#!/bin/bash
# Save the U-Boot environment as text (printenv) from the U-Boot console, then boot Linux again.
#   tools/uboot_env_backup.sh <out.txt>      (env: NAS=<serial host> BOARD=<ssh host of the board>)
# The binary environment (mtd env1/env2) is also part of a full flash backup:
#   cat /dev/mtd0ro /dev/mtd1ro /dev/mtd2ro /dev/mtd3ro > flash_full.bin
set -u
NAS=${NAS:-yuxia.yuxia228.mydns.jp}; BOARD=${BOARD:-sparrow-hawk}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath -m "$1")
scp -q "$HERE/uboot_run.py" "$NAS:/tmp/uboot_run.py"
LOG=$(mktemp)
ssh "$NAS" "python3 /tmp/uboot_run.py --timeout 150 --zephyr-wait 1 --cmd-timeout 30 --post boot 'printenv'" > "$LOG" 2>&1 &
PID=$!
sleep 3; ssh "$BOARD" 'sudo reboot' >/dev/null 2>&1 || true
wait $PID
# keep only the printenv output
sed -n '/^\[UBOOT\] printenv/,/^\[ZEPHYR-BEGIN\]/p' "$LOG" | sed '1d;$d' | sed '/^=> *$/d' > "$OUT"
rm -f "$LOG"
echo "saved $(wc -l < "$OUT") lines to $OUT"
for i in $(seq 1 60); do ssh -o ConnectTimeout=3 -o BatchMode=yes "$BOARD" true 2>/dev/null && { echo "[linux up]"; break; }; sleep 3; done
