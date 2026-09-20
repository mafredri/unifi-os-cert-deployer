#!/bin/sh
set -eu

certificate=${LEGO_HOOK_CERT_PATH##*/}
name=${certificate%.crt}
pending="${LEGO_PATH:-/data}/deploy/$name"
umask 077
mkdir -p "$pending"
cp "$LEGO_HOOK_CERT_PATH" "$pending/cert.pem"
cp "$LEGO_HOOK_CERT_KEY_PATH" "$pending/key.pem"
/usr/local/bin/deploy-pending "$pending"
