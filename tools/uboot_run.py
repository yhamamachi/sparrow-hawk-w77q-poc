#!/usr/bin/env python3
"""Drive the Sparrow Hawk U-Boot console (and capture the Zephyr console) over serial.
Run this on the PC that owns the serial ports.

  uboot_run.py --uboot /dev/ttyUSB0 --zephyr /dev/ttyUSB1 [--timeout 120] [--zephyr-wait 12] CMD [CMD ...]

It waits for the board to (re)boot, interrupts autoboot by sending keys, then runs each CMD at the
"=> " prompt. Start it, then reboot the board. After the commands it keeps reading the Zephyr
console for --zephyr-wait seconds. Everything is printed with a [UBOOT]/[ZEPHYR] prefix.
"""
import argparse, re, sys, threading, time
import serial

ap = argparse.ArgumentParser()
ap.add_argument('--uboot', default='/dev/ttyUSB0')
ap.add_argument('--zephyr', default='/dev/ttyUSB1')
ap.add_argument('--baud', type=int, default=921600)
ap.add_argument('--timeout', type=float, default=120)
ap.add_argument('--zephyr-wait', type=float, default=12)
ap.add_argument('--cmd-timeout', type=float, default=30)
ap.add_argument('--post', action='append', default=[], help='command(s) run after the Zephyr capture (e.g. boot); no prompt is awaited')
ap.add_argument('cmds', nargs='*')
a = ap.parse_args()

zlog = []
stop = False
def zreader():
    z = serial.Serial(a.zephyr, a.baud, timeout=0.2)
    while not stop:
        d = z.read(4096)
        if d:
            zlog.append((time.time(), d.decode(errors='replace')))
    z.close()
t = threading.Thread(target=zreader, daemon=True); t.start()

u = serial.Serial(a.uboot, a.baud, timeout=0.1)
PROMPT = re.compile(r'=> ?\s*$')
def readuntil(rx, timeout, spam=None):
    buf = ''; end = time.time() + timeout
    while time.time() < end:
        if spam: u.write(spam)
        d = u.read(4096)
        if d:
            buf += d.decode(errors='replace')
            if rx.search(buf[-40:]): return buf, True
    return buf, False

# drain stale output until the line is quiet (unless the board is rebooting: then output keeps coming)
quiet = time.time()
while time.time() - quiet < 1.0 and time.time() < quiet + 30:
    if u.read(65536): quiet = time.time()
out, ok = readuntil(PROMPT, a.timeout, spam=b'\n')   # send newline repeatedly to stop autoboot
print('[UBOOT-BOOT-TAIL]', out[-600:].replace('\r', ''))
if not ok:
    print('!! no U-Boot prompt'); sys.exit(2)
for c in a.cmds:
    u.write(c.encode() + b'\n')
    out, ok = readuntil(PROMPT, a.cmd_timeout)
    print('[UBOOT]', out.replace('\r', ''))
    if not ok: print('!! prompt timeout after:', c); break
t0 = time.time()
time.sleep(a.zephyr_wait)
stop = True; t.join(1)
print('[ZEPHYR-BEGIN]'); print(''.join(x for _, x in zlog).replace('\r', '')); print('[ZEPHYR-END]')
for c in a.post:
    u.write(c.encode() + b'\n'); print('[UBOOT-POST]', c)
