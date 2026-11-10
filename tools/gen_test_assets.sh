#!/bin/bash
# Generate test assets (no secrets are committed: keys are random and live in <out>/keys).
#   tools/gen_test_assets.sh <fw_dir with zephyr-v1.0.bin zephyr-v1.1.bin> <out_dir> <w77q_manifest binary>
# Version numbers handed to the W77Q rollback counter: v1.0 -> 10, v1.1 -> 11.
set -euo pipefail
FW=$(realpath "$1"); OUT=$(realpath -m "$2"); MAN=$(realpath "$3")
mkdir -p "$OUT/keys"
for k in good bad; do [ -f "$OUT/keys/$k.key" ] || { openssl rand -hex 32 > "$OUT/keys/$k.key"; chmod 600 "$OUT/keys/$k.key"; }; done
cp "$FW/zephyr-v1.0.bin" "$OUT/valid-v1.0.bin";  "$MAN" "$OUT/valid-v1.0.bin" 10 > "$OUT/valid-v1.0.manifest"
cp "$FW/zephyr-v1.1.bin" "$OUT/valid-v1.1.bin";  "$MAN" "$OUT/valid-v1.1.bin" 11 > "$OUT/valid-v1.1.manifest"
# NEXT_VER: a version number that the flash would ACCEPT (newer than v1.1). The attack cases use it, so a
# rejection can only be caused by the digest / authentication check, not by the rollback check.
NEXT_VER=${NEXT_VER:-12}
# tampered: manifest of the genuine image (newer version), but one byte of the image flipped afterwards
cp "$OUT/valid-v1.1.bin" "$OUT/tampered-v1.1.bin"
printf '\x5a' | dd of="$OUT/tampered-v1.1.bin" bs=1 seek=1000 conv=notrunc status=none
"$MAN" "$OUT/valid-v1.1.bin" "$NEXT_VER" > "$OUT/tampered-v1.1.manifest"
# invalid key case: genuine image + genuine (newer) manifest, installed with keys/bad.key
cp "$OUT/valid-v1.1.bin" "$OUT/badkey-v1.1.bin"; cp "$OUT/tampered-v1.1.manifest" "$OUT/badkey-v1.1.manifest"
# rollback = the validly produced v1.0 (older version number)
cp "$OUT/valid-v1.0.bin" "$OUT/rollback-v1.0.bin"; cp "$OUT/valid-v1.0.manifest" "$OUT/rollback-v1.0.manifest"
ls -l "$OUT"
