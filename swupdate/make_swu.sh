#!/bin/bash
# make_swu.sh <fw.bin> <fw.manifest> <out.swu> <sw-version>
# The .swu is signed with SWUpdate's own mechanism (CMS/PKCS#7, SWU_SIGN_KEY + SWU_SIGN_CERT; created by gen_swu_keys.sh).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
FW=$(realpath "$1"); MAN=$(realpath "$2"); OUT=$(realpath -m "$3"); VER=$4
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cp "$FW" "$T/zephyr.bin"; cp "$MAN" "$T/zephyr.manifest"
sed -e "s/@SHA_MAN@/$(sha256sum "$T/zephyr.manifest" | cut -d" " -f1)/" -e "s/@SHA_FW@/$(sha256sum "$T/zephyr.bin" | cut -d" " -f1)/" -e "s/@SECTION@/${SECTION:-4}/" -e "s/@VERSION@/$VER/" -e "s#@KEYFILE@#${KEYFILE:-/etc/w77q/full.key}#" "$HERE/sw-description.in" > "$T/sw-description"
: "${SWU_SIGN_KEY:?}" "${SWU_SIGN_CERT:?}"
openssl cms -sign -in "$T/sw-description" -out "$T/sw-description.sig" -signer "$SWU_SIGN_CERT" -inkey "$SWU_SIGN_KEY" \
  -outform DER -nosmimecap -binary
(cd "$T" && for f in sw-description sw-description.sig zephyr.manifest zephyr.bin; do echo $f; done | cpio -ov -H crc > "$OUT" 2>/dev/null)
ls -l "$OUT"
