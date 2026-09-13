FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1

WORKDIR /opt/nanaon/Nanaon-Private-Server

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY api ./api
COPY cdn ./cdn
COPY crypto ./crypto
COPY data ./data
COPY process_guard.py server.py ./

# The tracked data/private_server.sqlite3 is a seed only; the live database is
# bind-mounted over data/private_server.sqlite3 at runtime (see compose.yaml).
RUN mv data/private_server.sqlite3 seed.sqlite3 && \
    mkdir -p var/logs var/run compat_assets data

COPY deploy/entrypoint.sh /usr/local/bin/nanaon-entrypoint.sh
RUN chmod +x /usr/local/bin/nanaon-entrypoint.sh

ENTRYPOINT ["nanaon-entrypoint.sh"]
CMD ["--config", "config.cloudflare.yaml", "--host", "0.0.0.0", "--port", "8888"]
