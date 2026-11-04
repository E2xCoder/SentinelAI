# syntax=docker/dockerfile:1
#
# SentinelAI container image.
#
# Build (core only, or with the optional anomaly-detection extra):
#   docker build -t sentinelai .
#   docker build -t sentinelai:ai --build-arg EXTRAS=ai .
#
# One-off scan of the host's logs (read-only bind mount, state in a named volume):
#   docker run --rm -v /var/log:/host/log:ro -v sentinelai-state:/var/lib/sentinelai \
#       sentinelai scan /host/log/auth.log
#   (the container user is UID 10001; the host files must be readable by it,
#    e.g. via a group/ACL, or add `--group-add <gid of adm>` )
#
# Continuous monitoring (restart policy keeps it running):
#   docker run -d --name sentinelai --restart unless-stopped \
#       -v /var/log:/host/log:ro -v sentinelai-state:/var/lib/sentinelai \
#       -v /etc/sentinelai/config.yaml:/etc/sentinelai/config.yaml:ro \
#       --env-file /etc/sentinelai/sentinelai.env \
#       sentinelai --config /etc/sentinelai/config.yaml live
#   (set live.paths in the config to the /host/log/... paths)
#
# The container has no firewall privileges; keep response.enabled=false here.

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------- builder ----
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ARG EXTRAS=""

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src

# Build a wheel of the project only, then install it (plus deps) into a venv.
RUN pip wheel --no-deps --wheel-dir /wheels . \
    && python -m venv /opt/venv \
    && case "${EXTRAS}" in \
         *[!a-z,]*) echo "EXTRAS may only contain a-z and commas" >&2; exit 1 ;; \
       esac \
    && WHEEL="$(ls /wheels/sentinelai-*.whl)" \
    && if [ -n "${EXTRAS}" ]; then SPEC="${WHEEL}[${EXTRAS}]"; else SPEC="${WHEEL}"; fi \
    && /opt/venv/bin/pip install "${SPEC}"

# ------------------------------------------------------------------ final ----
FROM python:${PYTHON_VERSION}-slim-bookworm

LABEL org.opencontainers.image.title="SentinelAI" \
      org.opencontainers.image.description="AI-assisted security log analysis, detection and automated response platform for Linux systems." \
      org.opencontainers.image.source="https://github.com/E2xCoder/SentinelAI" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    SENTINELAI_STATE_DIR=/var/lib/sentinelai

# Non-root user with a fixed UID; no compilers or build tools in this stage.
RUN groupadd --system --gid 10001 sentinel \
    && useradd --system --uid 10001 --gid sentinel --no-create-home \
         --home-dir /var/lib/sentinelai --shell /usr/sbin/nologin sentinel \
    && mkdir -p /var/lib/sentinelai \
    && chown sentinel:sentinel /var/lib/sentinelai \
    && chmod 0700 /var/lib/sentinelai

COPY --from=builder /opt/venv /opt/venv

USER 10001:10001
WORKDIR /var/lib/sentinelai
VOLUME /var/lib/sentinelai

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["sentinel", "version"]

ENTRYPOINT ["sentinel"]
CMD ["--help"]
