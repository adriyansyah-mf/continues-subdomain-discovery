# BBOT worker image. BBOT is installed in its own virtualenv (/opt/bbot) because its
# dependency pins differ from the platform's; the platform worker invokes its CLI.
# Build context: repository root.
ARG PYTHON_IMAGE=python:3.12.14-slim-bookworm
FROM ${PYTHON_IMAGE}
ARG BBOT_VERSION=3.0.2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/bb \
    HOME=/home/bb \
    BBOT_BINARY=/opt/bbot/bin/bbot \
    BBOT_VERSION=${BBOT_VERSION}

# BBOT's core system dependencies (it would otherwise try to `sudo apt install` them at runtime).
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip curl git make gcc tar xz-utils p7zip-full libssl-dev openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system --gid 10001 bb \
    && useradd --system --uid 10001 --gid bb --home /home/bb --create-home bb
RUN python -m venv /opt/bbot && /opt/bbot/bin/pip install "bbot==${BBOT_VERSION}"

WORKDIR /opt/bb
COPY apps/orchestrator/pyproject.toml apps/orchestrator/pyproject.toml
COPY apps/orchestrator/app apps/orchestrator/app
RUN pip install ./apps/orchestrator
COPY workers ./workers

USER bb
# Pre-warm BBOT's one-time setup (core-deps check, Ansible collection) into the home directory
# image layer; the named volume mounted at /home/bb is initialised from it on first use.
RUN /opt/bbot/bin/bbot -t example.com -m crt --dry-run -y --no-deps > /dev/null 2>&1 || true
ENTRYPOINT ["python", "-m"]
CMD ["workers.bbot"]
