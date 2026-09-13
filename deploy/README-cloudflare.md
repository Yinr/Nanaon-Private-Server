# Cloudflare deployment

This deployment uses two containers in one Compose project:

- `nanaon-caddy`: terminates TLS on host port 443 and proxies to `nanaon-app:8888`.
- `nanaon-app`: runs the Flask API and integrated asset routes on port 8888.

The host paths expected by `cdn/asset_server.py` are siblings of the server
directory. The Compose file mounts them at `/opt/nanaon/` and keeps the large
resource trees read-only.

## Origin CA mode (default)

Create an Origin CA certificate for `nanaon.0000227.xyz` in the Cloudflare
account that owns `0000227.xyz`. Put the two files below in `deploy/secrets/`:

```text
nanaon-origin.crt
nanaon-origin.key
```

Keep the key out of Git and set Cloudflare SSL/TLS mode to `Full (strict)`.

From this directory:

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f nanaon-app nanaon-caddy
```

## Let's Encrypt alternative

Remove the explicit `tls` line from `Caddyfile`. For HTTP-01, publish
`80:80` and allow Cloudflare/Let's Encrypt validation traffic. For DNS-01,
build Caddy with the Cloudflare DNS module and provide a least-privilege DNS
API token; keep Caddy's `/data` volume persistent.

## Repository and deployment boundaries

The reproducible deployment definition is kept in this directory:

- `compose.yaml`: the internal app on `8888` and the public Caddy listener on `443`.
- `Caddyfile`: Origin CA TLS, static download caching, API no-store, and asset caching.
- `Dockerfile`: image build for the app process.
- `config.cloudflare.yaml`: the domain-specific app configuration for
  `nanaon.0000227.xyz`.
- `site/index.html`: the static download and installation page.

Large release files under `site/downloads/` are deployment artifacts and are ignored
by Git. Upload them separately and keep `SHA256SUMS.txt` beside the files. The current
site uses the Nanaon APK/XAPK/OBB releases and an APKPure Installer backup.

The following inputs remain outside the repository:

- `deploy/secrets/nanaon-origin.crt` and `deploy/secrets/nanaon-origin.key`: Origin CA
  certificate and private key; the directory must stay private.
- The two read-only resource roots mounted by Compose:
  `/opt/nanaon/main.5465.com.aniplex.nananiji` and
  `/opt/nanaon/com.aniplex.nananiji`.
- `data/`, `var/`, and the persistent Caddy volumes: runtime state and caches.

On a host laid out as `/opt/nanaon/`, place the server checkout at
`/opt/nanaon/Nanaon-Private-Server/` and the two resource roots beside it. Then run
the commands above from `deploy/`.
