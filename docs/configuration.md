# Configuration and recovery

The [README](../README.md) covers the standalone CLI and the published container. The [.env example](../.env.example) is a starting point for one console.

Compose loads `.env` into the container, including any DNS provider variables and named target settings you add. When running the CLI directly, export those variables into its environment.

## Credentials and TLS

UniFi credentials can be supplied as `UNIFI_USERNAME` and `UNIFI_PASSWORD`, or through `UNIFI_USERNAME_FILE` and `UNIFI_PASSWORD_FILE`. Set either a value or its file path, not both. The Compose example mounts `./secrets` at `/run/secrets` read-only; paths in `.env` refer to the files inside the container.

DNS credentials use the environment variables supported by your [lego provider](https://go-acme.github.io/lego/dns/). Use its `_FILE` settings when supported, or put the values directly in `.env`. For literal values containing `$`, use single quotes in `.env` to prevent Compose interpolation.

TLS verification is enabled by default. To connect to a console with a self-signed certificate, set `UNIFI_SKIP_TLS_VERIFY=true`. Named targets use their own setting, such as `UNIFI_HOME_SKIP_TLS_VERIFY=true`; they do not inherit the global setting. Remove the override once the console serves a trusted certificate chain.

## Multiple certificates and consoles

Certificate jobs define what lego issues. Upload targets define which consoles receive each certificate. A target's `DOMAIN` must exactly match a domain in the certificate job; wildcards match literally.

For two independent certificates, replace the single-console settings in `.env` with:

```dotenv
LEGO_CERTIFICATES=home,protect
LEGO_HOME_DOMAINS=unifi.home.example.com
LEGO_PROTECT_DOMAINS=protect.home.example.com

UNIFI_TARGETS=home,protect
UNIFI_HOME_DOMAIN=unifi.home.example.com
UNIFI_HOME_URL=https://unifi.home.example.com
UNIFI_HOME_USERNAME_FILE=/run/secrets/home-username
UNIFI_HOME_PASSWORD_FILE=/run/secrets/home-password
UNIFI_HOME_CERT_NAME="deployer: home"

UNIFI_PROTECT_DOMAIN=protect.home.example.com
UNIFI_PROTECT_URL=https://protect.home.example.com
UNIFI_PROTECT_USERNAME_FILE=/run/secrets/protect-username
UNIFI_PROTECT_PASSWORD_FILE=/run/secrets/protect-password
UNIFI_PROTECT_CERT_NAME="deployer: protect"
```

Keep your shared ACME email, DNS provider, and provider credentials in `.env`. Create the corresponding credential files in `secrets/`.

Each target supports `USERNAME`, `PASSWORD`, `HTTP_TIMEOUT`, `SKIP_TLS_VERIFY`, `CERT_NAME`, and `CLEANUP` under its own `UNIFI_<ID>_` name. Global single-target settings are not inherited. Identifiers are case-insensitive and empty comma-separated entries are ignored. Target identifiers use letters, digits, and underscores; duplicate targets are rejected.

Each certificate job requires `LEGO_<ID>_DOMAINS` and uses its identifier as the storage name, such as `home.crt` and `home.key`. Keep job identifiers stable to reuse saved certificates. A failed job or target does not prevent the remaining configured jobs or selected targets from being attempted.

### Share one certificate

Keep both upload targets above, but replace the certificate job settings with:

```dotenv
LEGO_CERTIFICATES=shared
LEGO_SHARED_DOMAINS=unifi.home.example.com,protect.home.example.com
```

Both consoles receive the same certificate and private key, covering both domains.

Without `LEGO_CERTIFICATES`, lego uses `LEGO_DOMAINS` for one certificate. The example sets `LEGO_CERT_NAME=unifi` for its storage name. Without `LEGO_CERT_NAME`, lego uses the first domain. Named jobs override `LEGO_CERT_NAME` with their job identifier.

## Certificate names and cleanup

`--name` or `UNIFI_CERT_NAME` sets the literal name displayed in UniFi. The CLI appends a space and the first eight hexadecimal characters of the certificate's SHA-1 fingerprint: `deployer: home d4ac8b21`.

Repeated uploads reuse a same-name record only when its full fingerprint matches, activating it if needed. A conflicting fingerprint is an error.

`--cleanup` or `UNIFI_CLEANUP=true` removes expired, inactive certificates whose names begin with the configured name and a space. Cleanup is disabled by default and runs only after successful deployment. Explicit `--name` and `--cleanup` flags override environment settings for the selected targets.

## Hooks and certificate inputs

The CLI accepts `--cert` and `--key`, or `UNIFI_CERT_FILE` and `UNIFI_KEY_FILE`. It also reads lego's deploy-hook paths and `fullchain.pem` and `privkey.pem` from Certbot's `RENEWED_LINEAGE`. Make the UniFi credentials available to the hook process.

For lego:

```sh
lego run --dns hurricane --domains example.com \
  --email ops@example.com --deploy-hook /path/to/unifi-cert-upload
```

For Certbot:

```sh
certbot renew --deploy-hook /path/to/unifi-cert-upload
```

Lego supplies the certificate domains used for automatic multi-target selection. With other issuers, or to select one target explicitly, use `--target`:

```sh
certbot renew --deploy-hook '/path/to/unifi-cert-upload --target home'
```

External issuers may not repeat a failed deploy hook until the next renewal. Rerun the CLI with the saved certificate and key to retry.

## Scheduling and recovery

The container checks renewal once daily at a random hour and minute selected at startup. Set `CRON_SCHEDULE` in `.env` to override that schedule.

Failed deployments leave `fullchain.pem` and `key.pem` in `/data/deploy/<certificate-name>/`. Startup and scheduled runs retry those copies, including when lego skips renewal or fails. Successful deployment removes the pending copies. If you repurpose a job's domain mapping, clear its old pending files first.

To retry pending uploads immediately:

```sh
docker compose exec unifi-os-le-cert-deployer /usr/local/bin/deploy-pending
```

To upload a saved certificate manually with the single-console defaults:

```sh
docker compose run --rm --entrypoint /usr/local/bin/unifi-cert-upload \
  unifi-os-le-cert-deployer \
  --cert /data/certificates/unifi.crt --key /data/certificates/unifi.key
```

For named targets, add `--target home` and use that job's saved certificate paths. A successful target is not uploaded again when retrying a partially failed deployment.

Keep the `certificate_state` volume. `docker compose down -v` deletes the stored account, certificates, and pending uploads.
