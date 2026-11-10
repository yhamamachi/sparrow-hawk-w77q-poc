#!/bin/bash
# Reboot the board, stop U-Boot, load the Zephyr image from the W77Q section and start the R52,
# print the Zephyr UART output, then let the board boot Linux again.
#   tools/r52_run.sh            (env: NAS=<serial host> BOARD=<ssh host of the board> OFFSET=0x1000000)
NAS=${NAS:-yuxia.yuxia228.mydns.jp}; BOARD=${BOARD:-sparrow-hawk}; OFFSET=${OFFSET:-0x1000000}
HERE=$(cd "$(dirname "$0")" && pwd)
scp -q "$HERE/uboot_run.py" "$NAS:/tmp/uboot_run.py"
LOG=$(mktemp)
ssh "$NAS" "python3 /tmp/uboot_run.py --timeout 150 --zephyr-wait 12 --post boot \
  'sf probe' 'sf read 0x40040000 $OFFSET 0x80000' 'rproc init' 'rproc load 0 0x40040000 0x200000' 'rproc start 0'" > "$LOG" 2>&1 &
PID=$!
sleep 3; ssh "$BOARD" 'sudo reboot' >/dev/null 2>&1 || true
wait $PID
sed -n '/\[UBOOT\] sf probe/,$p' "$LOG" | grep -v '^$'
# wait for Linux to come back
for i in $(seq 1 60); do ssh -o ConnectTimeout=3 -o BatchMode=yes "$BOARD" true 2>/dev/null && { echo "[linux up]"; break; }; sleep 3; done
rm -f "$LOG"
