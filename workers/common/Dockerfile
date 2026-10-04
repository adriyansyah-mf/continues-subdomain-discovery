# Common scanner/worker image. One image, many workers: the compose service picks
# the worker module (python -m workers.<name>). Build context: repository root.
#
# Tool versions are pinned build args (never "latest"). To update a tool, bump the
# ARG here and in .env.example, rebuild, and run the worker tests (docs/operations.md).
ARG PYTHON_IMAGE=python:3.12.14-slim-bookworm

# ---- stage 1: fetch + verify pinned ProjectDiscovery binaries -------------------
FROM debian:bookworm-20260918-slim AS tools
ARG HTTPX_VERSION=1.12.0
ARG TLSX_VERSION=1.4.0
ARG MAPCIDR_VERSION=1.1.97
ARG KATANA_VERSION=1.7.0
ARG UNCOVER_VERSION=1.2.1
ARG NUCLEI_VERSION=3.11.1
ARG TARGETARCH=amd64
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/install-tools.sh /usr/local/bin/install-tools.sh
RUN TARGETARCH=${TARGETARCH} install-tools.sh /out \
      httpx=${HTTPX_VERSION} tlsx=${TLSX_VERSION} mapcidr=${MAPCIDR_VERSION} \
      katana=${KATANA_VERSION} uncover=${UNCOVER_VERSION} nuclei=${NUCLEI_VERSION}

# ---- stage 1b: clone + verify the pinned nuclei-templates release ----------------
# Templates are scanner configuration: pinned at build time (tag + commit SHA),
# shipped in the image and never fetched or updated at runtime (-duc, read-only layer).
FROM debian:bookworm-20260918-slim AS nuclei-templates
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
ARG NUCLEI_TEMPLATES_COMMIT=893122ffce8ebf8e264f15d2cd3960cb1dd36d6c
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY scripts/install-nuclei-templates.sh /usr/local/bin/install-nuclei-templates.sh
RUN install-nuclei-templates.sh /out ${NUCLEI_TEMPLATES_VERSION} ${NUCLEI_TEMPLATES_COMMIT}

# ---- stage 2: runtime --------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ARG HTTPX_VERSION=1.12.0
ARG TLSX_VERSION=1.4.0
ARG MAPCIDR_VERSION=1.1.97
ARG KATANA_VERSION=1.7.0
ARG UNCOVER_VERSION=1.2.1
ARG NUCLEI_VERSION=3.11.1
ARG NUCLEI_TEMPLATES_VERSION=10.4.9
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/opt/bb \
    HTTPX_VERSION=${HTTPX_VERSION} \
    TLSX_VERSION=${TLSX_VERSION} \
    MAPCIDR_VERSION=${MAPCIDR_VERSION} \
    KATANA_VERSION=${KATANA_VERSION} \
    UNCOVER_VERSION=${UNCOVER_VERSION} \
    NUCLEI_VERSION=${NUCLEI_VERSION} \
    NUCLEI_TEMPLATES_VERSION=${NUCLEI_TEMPLATES_VERSION} \
    HOME=/tmp \
    PD_BIN_DIR=/opt/pd/bin \
    HTTPX_BINARY=/opt/pd/bin/httpx \
    TLSX_BINARY=/opt/pd/bin/tlsx \
    MAPCIDR_BINARY=/opt/pd/bin/mapcidr \
    KATANA_BINARY=/opt/pd/bin/katana \
    UNCOVER_BINARY=/opt/pd/bin/uncover \
    NUCLEI_BINARY=/opt/pd/bin/nuclei \
    NUCLEI_TEMPLATES_DIR=/opt/pd/nuclei-templates \
    NUCLEI_TEMPLATES_RELEASE_FILE=/opt/pd/nuclei-templates-release

RUN groupadd --system --gid 10001 bb && useradd --system --uid 10001 --gid bb --home /opt/bb bb
WORKDIR /opt/bb
# ProjectDiscovery binaries live in their own directory: the Python `httpx` client library
# installs an unrelated `httpx` console script into /usr/local/bin.
COPY --from=tools /out/ /opt/pd/bin/
COPY --from=nuclei-templates /out/nuclei-templates /opt/pd/nuclei-templates
COPY --from=nuclei-templates /out/nuclei-templates-release /opt/pd/nuclei-templates-release

COPY apps/orchestrator/pyproject.toml apps/orchestrator/pyproject.toml
COPY apps/orchestrator/app apps/orchestrator/app
RUN pip install ./apps/orchestrator
COPY workers ./workers

USER bb
ENTRYPOINT ["python", "-m"]
CMD ["workers.httpx"]
