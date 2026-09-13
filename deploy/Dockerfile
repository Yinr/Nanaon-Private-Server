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
COPY server.py ./
COPY deploy/serve.py ./serve.py

RUN mkdir -p var/logs var/run compat_assets data

# serve.py pins the asset roots to the mounted resource trees and serves the
# app with waitress; the live database location comes from NANAON_DB_PATH
# (see compose.yaml). Upstream's server.py is a library without __main__.
ENTRYPOINT ["python", "serve.py"]
