#!/bin/bash
# Creates a throw-away code-signing key/cert for the .swu (PoC only; never commit the key).
#   gen_swu_keys.sh <out_dir>  -> swu-sign.key swu-sign.crt (the .crt is given to `swupdate -k`)
set -euo pipefail
O=$1; mkdir -p "$O"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=w77q-poc-swu" -keyout "$O/swu-sign.key" -out "$O/swu-sign.crt" \
  -addext "keyUsage=digitalSignature" -addext "extendedKeyUsage=emailProtection" 2>/dev/null
chmod 600 "$O/swu-sign.key"; ls "$O"
