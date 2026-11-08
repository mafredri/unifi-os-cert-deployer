#!/bin/sh
# Usage: image-test.sh IMAGE
#
# Checks the parts of the lego base image that the scripts depend on: the
# lego run environment variables and the tools the entrypoint and cron jobs
# call. Issuing a certificate needs an ACME server, so this does not run lego.
set -eu

image=$1
status=0

help=$(docker run --rm --entrypoint /lego "$image" run -h)
for variable in LEGO_CERT_NAME LEGO_DOMAINS LEGO_PATH LEGO_DEPLOY_HOOK; do
	if ! printf '%s\n' "$help" | grep -qw "$variable"; then
		printf 'FAIL: lego run -h does not list %s\n' "$variable" >&2
		status=1
	fi
done

for tool in awk crond od printenv sed tr; do
	if ! docker run --rm --entrypoint /bin/sh "$image" -c "command -v $tool" >/dev/null; then
		printf 'FAIL: %s is not in the image\n' "$tool" >&2
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "unifi-os-le-cert-deployer: OK"
fi
exit "$status"
