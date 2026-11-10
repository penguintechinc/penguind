# syntax=docker/dockerfile:1.7
# hub-api: Quart service served by hypercorn. Rootless (uid 10001), stateless,
# compatible with readOnlyRootFilesystem (writable paths are mounted emptyDirs at runtime).
# Build context: services/hub-api/ (needs requirements.txt with hashes, and app/ package).

FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
RUN python -m venv /opt/venv
COPY requirements.txt ./
# Hash-pinned install: pip refuses anything not listed with a --hash entry.
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r requirements.txt

FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser
COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY app/ /srv/app/
USER 10001:10001
EXPOSE 8080
# Exec form, absolute interpreter path: matches the Tetragon exec allowlist in the chart.
ENTRYPOINT ["/opt/venv/bin/python", "-m", "hypercorn"]
CMD ["--bind", "0.0.0.0:8080", "app:create_app()"]
