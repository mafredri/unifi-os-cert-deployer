# unifi-os-cert-deployer

A CLI for uploading and managing UniFi OS certificates, with a Docker and [lego](https://go-acme.github.io/lego/) setup for automated Let's Encrypt issuance, renewal, and deployment.

## Upload certificates

Build with `make build`, then use a UniFi OS account with permission to manage console certificates:

```sh
export UNIFI_URL=https://console.example.com
export UNIFI_USERNAME_FILE=/path/to/unifi_username
export UNIFI_PASSWORD_FILE=/path/to/unifi_password
bin/unifi-cert-upload --cert /path/to/fullchain.pem --key /path/to/privkey.pem
```

Uploads activate automatically. Use `--name` to customize the certificate name and `--cleanup` to remove expired, inactive certificates managed under that name. See `--help` or [hook configuration](docs/configuration.md#hooks-and-certificate-inputs) for lego and Certbot.

## Docker and lego

Run the published image, `ghcr.io/mafredri/unifi-os-cert-deployer:latest`, with Compose:

```sh
curl -fsSLO https://raw.githubusercontent.com/mafredri/unifi-os-cert-deployer/main/compose.yaml
curl -fsSL https://raw.githubusercontent.com/mafredri/unifi-os-cert-deployer/main/.env.example -o .env
mkdir -p secrets
```

Edit `.env` for your console, domains, email, and [DNS provider](https://go-acme.github.io/lego/dns/). Put credentials in the referenced files under `secrets/`, or configure their environment variables in `.env`.

```sh
docker compose up -d
docker compose logs -f
```

Renewal runs daily; failed deployments are retried automatically. Preserve the `certificate_state` volume when updating.

See [configuration](docs/configuration.md) for multiple certificates and consoles, TLS settings, and recovery. Compose pulls the published image by default; from a source checkout, use `docker compose up -d --build` to build locally.

## Development

`make build` builds the CLI, `make check` runs checks, and `make image` builds a local image.
