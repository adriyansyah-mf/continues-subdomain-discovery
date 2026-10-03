# Orchestrator image: FastAPI API, scheduler, migrations and the bbctl CLI.
# Build context: repository root.
ARG PYTHON_IMAGE=python:3.12.14-slim-bookworm
FROM ${PYTHON_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 bb && useradd --system --uid 10001 --gid bb --home /opt/bb bb
WORKDIR /opt/bb

COPY apps/orchestrator/pyproject.toml apps/orchestrator/pyproject.toml
COPY apps/orchestrator/app apps/orchestrator/app
RUN pip install ./apps/orchestrator

COPY alembic.ini ./
COPY migrations ./migrations

USER bb
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
