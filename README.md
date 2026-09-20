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

Names combine the configured name, a space, and the first eight hexadecimal characters of the certificate's SHA-1 fingerprint: `--name 'deployer: unifi.example.com'` produces names such as `deployer: unifi.example.com d4ac8b21`.

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

## Automate with Docker and lego

The included Compose setup handles Let's Encrypt certificates through DNS validation and deploys them to UniFi OS. It runs at startup and checks for renewal daily, keeping certificate state in a persistent volume.

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

If certificate issuance succeeds but deployment fails, retry the upload:

```sh
docker compose run --rm --entrypoint /usr/local/bin/unifi-cert-upload \
  unifi-os-le-cert-deployer \
  --cert /data/certificates/unifi.crt \
  --key /data/certificates/unifi.key
```
