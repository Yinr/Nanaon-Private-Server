"""Standalone app entrypoint for the container deployment.

Upstream turned server.py into a library (create_app/load_config) and ships an
interactive LAN launcher instead; this module serves the API+CDN app directly
for the deploy/ compose stack without modifying upstream files. Asset roots
are pinned to the mounted resource trees the same way lan_launcher.py does.
"""

import os
from pathlib import Path

from waitress import serve

from server import create_app, load_config
# Import the singleton instance (like upstream lan_launcher.py), not the
# module: cdn.asset_server is the module, cdn.asset_server.asset_server the
# AssetServer() instance whose roots the handlers actually read.
from cdn.asset_server import asset_server


def main() -> None:
    base = Path(__file__).resolve().parent
    resource_root = Path(os.environ.get("NANAON_RESOURCE_ROOT", str(base.parent)))

    asset_server.ASSET_BASE = resource_root / "main.5465.com.aniplex.nananiji" / "assets"
    asset_server.CACHE_BASE = resource_root / "com.aniplex.nananiji"
    asset_server.DOWNLOAD_CACHE = asset_server.CACHE_BASE / "files" / "DownloadCache"

    config = load_config(os.environ.get("NANAON_CONFIG", "config.cloudflare.yaml"))
    app = create_app(config)

    serve(
        app,
        host=os.environ.get("NANAON_APP_HOST", "0.0.0.0"),
        port=int(os.environ.get("NANAON_APP_PORT", "8888")),
        threads=int(os.environ.get("NANAON_APP_THREADS", "12")),
    )


if __name__ == "__main__":
    main()
