#!/bin/sh
set -eu

cd /opt/nanaon/Nanaon-Private-Server

# The live database is bind-mounted at data/private_server.sqlite3. When the
# host file is empty (fresh install or explicit reset), reseed it.
if [ ! -s data/private_server.sqlite3 ] && [ -s seed.sqlite3 ]; then
    echo "[entrypoint] empty database; seeding from seed.sqlite3"
    cp seed.sqlite3 data/private_server.sqlite3
fi

exec python server.py "$@"
