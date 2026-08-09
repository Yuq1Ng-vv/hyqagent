# docker/sandbox/Dockerfile — Minimal Docker sandbox for PoC execution.
#
# Build:
#   docker build -t hyqagent-sandbox:latest docker/sandbox/
#
# Safety constraints are enforced at container run time by SandboxExecutor:
#   --network=none  --read-only  --tmpfs /tmp  --memory=256m
#   --cpu-quota=50000  --user=nobody  timeout=30s
#
# This image provides ONLY the interpreters; the orchestrator applies the
# isolation flags on every `docker run`.

FROM python:3.12-slim

# Common utilities for PoC scripts (read-only verification only)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user — container is always launched with --user=nobody
RUN useradd --create-home --shell /bin/bash sandbox
USER sandbox
WORKDIR /sandbox

# Mark the image as intentionally minimal
LABEL org.hyqagent.sandbox="true"
LABEL org.hyqagent.version="0.1.0"
