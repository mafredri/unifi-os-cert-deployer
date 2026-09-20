#!/bin/sh
set -eu
set -f

jobs=$(printf '%s' "${LEGO_CERTIFICATES:-}" | tr ',' '\n' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; /^$/d')
status=0
if [ -z "$jobs" ]; then
	/lego run || status=1
else
	old_ifs=$IFS
	IFS='
'
	for job in $jobs; do
		IFS=$old_ifs
		id=$(printf '%s' "$job" | tr '[:upper:]' '[:lower:]')
		variable="LEGO_$(printf '%s' "$id" | tr '[:lower:]' '[:upper:]')_DOMAINS"
		if ! domains=$(printenv "$variable") || [ -z "$domains" ]; then
			printf 'Certificate job %s requires %s.\n' "$id" "$variable" >&2
			status=1
			continue
		fi
		LEGO_CERT_NAME="$id" LEGO_DOMAINS="$domains" /lego run || status=1
	done
fi

/usr/local/bin/deploy-pending || status=1
exit "$status"
