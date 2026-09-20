#!/bin/sh
set -eu

if [ -n "${CRON_SCHEDULE:-}" ]; then
	schedule=$CRON_SCHEDULE
else
	minute=$(od -An -N2 -tu2 /dev/urandom)
	hour=$(od -An -N2 -tu2 /dev/urandom)
	schedule="$((minute % 60)) $((hour % 24)) * * *"
fi

newline=$(printf '\nx')
newline=${newline%x}
case "$schedule" in
	*"$newline"*)
		printf '%s\n' 'CRON_SCHEDULE must be a single line.' >&2
		exit 1
		;;
esac

if ! printf '%s\n' "$schedule" | awk 'NF != 5 { exit 1 }'; then
	printf '%s\n' 'CRON_SCHEDULE must contain five cron fields.' >&2
	exit 1
fi

printf '%s /lego run\n' "$schedule" > /etc/crontabs/root
chmod 0600 /etc/crontabs/root

if ! /lego run; then
	printf '%s\n' 'Initial lego run failed; cron will try again at the next scheduled time.' >&2
fi

exec crond -f -l 2
