# unifi-os-cert-deployer

A CLI for uploading and managing UniFi OS certificates, with a ready-to-use Docker and lego setup for automated Let's Encrypt issuance, renewal, and deployment.

## Upload certificates

Use `unifi-cert-upload` with certificates from your existing issuer, either directly or as a renewal hook. It uploads the certificate and activates it on your UniFi OS console.

Build the CLI with Go, then set your console credentials and upload a certificate:

```sh
make build

export UNIFI_URL=https://console.example.com
export UNIFI_USERNAME_FILE=/path/to/unifi_username
export UNIFI_PASSWORD_FILE=/path/to/unifi_password
bin/unifi-cert-upload --cert /path/to/cert.pem --key /path/to/key.pem
```

You can also supply credentials through `UNIFI_USERNAME` and `UNIFI_PASSWORD`, and certificate paths through `UNIFI_CERT_FILE` and `UNIFI_KEY_FILE`. For a console with a self-signed certificate, `UNIFI_SKIP_TLS_VERIFY=true` disables TLS certificate verification.

Add `--cleanup` to remove expired, inactive certificates with the same configured name. Set the name with `--name`, or use `UNIFI_CLEANUP` and `UNIFI_CERT_NAME` for hooks and Docker. Cleanup is disabled by default. Run `bin/unifi-cert-upload --help` for the CLI options.

Names combine the configured name, a space, and the first eight hexadecimal characters of the certificate's SHA-1 fingerprint: `--name 'deployer: unifi.example.com'` produces names such as `deployer: unifi.example.com d4ac8b21`. Repeated runs reuse a record with the same name and full fingerprint, activating it if needed. A name collision with a different fingerprint is an error.

### Renewal hooks

The CLI reads certificate paths from lego and Certbot deploy hooks. Make the UniFi credentials above available to the hook process.

For lego, set `LEGO_NO_BUNDLE=true` to upload the leaf certificate and add the deploy hook to your issuance command:

```sh
LEGO_NO_BUNDLE=true lego run --dns hurricane --domains example.com \
  --email ops@example.com --deploy-hook /path/to/unifi-cert-upload
```

For Certbot:

```sh
certbot renew --deploy-hook /path/to/unifi-cert-upload
```

If deployment fails after issuance, rerun the CLI with the saved certificate and key. The issuer may not call the hook again until the next renewal.

### Multiple targets

Set `UNIFI_TARGETS` and configure each target through its uppercase identifier:

```sh
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

Export these variables for the CLI, or put them in `.env` for Docker. Target identifiers are case-insensitive and use letters, digits, and underscores; empty entries are ignored. Each target also supports `USERNAME`, `PASSWORD`, `HTTP_TIMEOUT`, `SKIP_TLS_VERIFY`, and `CLEANUP` settings under its own `UNIFI_<ID>_` name. Target settings use their own defaults; global single-target settings are not inherited.

Lego's hook sends the certificate to every target whose `DOMAIN` exactly matches an entry in `LEGO_HOOK_CERT_DOMAINS`. Wildcards match literally. The Docker setup below supports both shared and independent certificates.

Use `--target home` for a manual upload or retry to just that target, including with a Certbot hook:

```sh
bin/unifi-cert-upload --target home --cert /path/to/cert.pem --key /path/to/key.pem
```

Other selected targets are still attempted if one fails. Rerunning the CLI skips certificates that are already active and retries incomplete deployments. Explicit `--name` and `--cleanup` flags override those settings for the selected targets.

## Automate with Docker and lego

The included Compose setup handles Let's Encrypt certificates through DNS validation and deploys them to UniFi OS. It runs at startup and checks for renewal daily, keeping certificates and pending deployments in a persistent volume.

Copy the example configuration:

```sh
cp .env.example .env
cp .env.dns.example .env.dns
mkdir -p secrets
chmod 700 secrets
```

Set your console URL, domains, email, and DNS provider in `.env`. Put the console username in `secrets/unifi_username` and password in `secrets/unifi_password`, one value per file.

Configure your provider's credentials in `.env.dns`, following [lego's DNS provider documentation](https://go-acme.github.io/lego/dns/). The example uses Hurricane Electric and expects `secrets/hurricane_tokens` containing `record-name:token`.

Build and start the container:

```sh
chmod 600 secrets/*
docker compose up --build -d
docker compose logs -f unifi-os-le-cert-deployer
```

Set `CRON_SCHEDULE` in `.env` to override the default daily schedule. Keep the `certificate_state` volume when recreating the container; `docker compose down -v` deletes it.

The deploy hook copies the certificate and key into `/data/deploy/<job>/`. Successful deployment removes that pending copy. Pending deployments are retried at startup and after each scheduled lego run, even when renewal is skipped or fails.

To retry a saved certificate manually, including an upload that failed before it was queued:

```sh
docker compose run --rm --entrypoint /usr/local/bin/unifi-cert-upload \
  unifi-os-le-cert-deployer \
  --cert /data/certificates/unifi.crt \
  --key /data/certificates/unifi.key
```

### Independent or shared certificates

For separate certificates and private keys in one container, add certificate jobs to `.env`:

```dotenv
LEGO_CERTIFICATES=home,protect
LEGO_HOME_DOMAINS=unifi.home.example.com
LEGO_PROTECT_DOMAINS=protect.home.example.com
```

Configure the upload targets as shown in **Multiple targets**. Each job's domain list determines which targets receive its certificate. Jobs share the ACME account and DNS provider settings; a failed job does not prevent the remaining jobs from running.

For one certificate shared by both targets, use a single job:

```dotenv
LEGO_CERTIFICATES=shared
LEGO_SHARED_DOMAINS=unifi.home.example.com,protect.home.example.com
```

Job identifiers are case-insensitive; empty entries are ignored. Each listed job requires `LEGO_<ID>_DOMAINS`; its identifier becomes the certificate's storage name, such as `/data/certificates/home.crt` and `home.key`. Keep identifiers stable to reuse saved certificates.

Without `LEGO_CERTIFICATES`, the container uses `LEGO_DOMAINS` and `LEGO_CERT_NAME` for a single certificate. Compose defaults the storage name to `unifi`; outside Compose it defaults to the first domain.
