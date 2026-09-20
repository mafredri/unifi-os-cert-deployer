#!/bin/sh
set -eu

status=0
if [ "$#" -eq 0 ]; then
	set -- "${LEGO_PATH:-/data}"/deploy/*
fi
for pending do
	[ -d "$pending" ] || continue
	name=${pending##*/}
	variable="LEGO_$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')_DOMAINS"
	domains=$(printenv "$variable" || printf '%s' "${LEGO_DOMAINS:-}")
	if LEGO_HOOK_CERT_DOMAINS="$domains" /usr/local/bin/unifi-cert-upload \
		--cert "$pending/fullchain.pem" --key "$pending/key.pem"; then
		rm "$pending/fullchain.pem" "$pending/key.pem"
		rmdir "$pending"
	else
		status=1
	fi
done
exit "$status"
