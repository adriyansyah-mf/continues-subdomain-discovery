# Bug bounty platform - developer entrypoints.
SHELL := /bin/bash
COMPOSE ?= docker compose
DEV_COMPOSE := $(COMPOSE) -f compose.yaml -f compose.dev.yaml
PY ?= .venv/bin/python


.PHONY: backup restore
.PHONY: help env build up up-dev down restart logs bootstrap health test test-integration lint format typecheck \
        migrate reset clean bbctl lab-program venv ps \
        autoscale autoscale-dev autoscale-dry

help:  ## show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  %-18s %s\n",$$1,$$2}'

env:  ## create .env with random secrets (does not overwrite)
	@./scripts/bootstrap.sh env

build:  ## build platform images
	$(COMPOSE) build

up: env  ## start the core stack
	$(COMPOSE) up -d

up-dev: env  ## start the stack + dev overlay (lab target, exposed DB ports)
	$(DEV_COMPOSE) up -d

down:  ## stop containers (keeps volumes)
	$(DEV_COMPOSE) down --remove-orphans

restart:  ## restart platform services
	$(COMPOSE) restart orchestrator scheduler notifier cve-monitor httpx-worker tlsx-worker dns-worker logstash

ps:
	$(DEV_COMPOSE) ps

logs:  ## follow logs (SERVICE=name to filter)
	$(DEV_COMPOSE) logs -f --tail=200 $(SERVICE)

bootstrap:  ## import bounty-targets-data (first-run bootstrap)
	./scripts/import-bounty-targets.sh

health:  ## check every service
	./scripts/healthcheck.sh

autoscale:  ## run the worker autoscaler in the foreground (core stack)
	$(PY) scripts/autoscale.py --compose-file compose.yaml $(AUTOSCALE_ARGS)

autoscale-dev:  ## autoscaler for the dev stack (keeps new replicas on the lab network)
	$(PY) scripts/autoscale.py --compose-file compose.yaml --compose-file compose.dev.yaml $(AUTOSCALE_ARGS)

autoscale-dry:  ## print one round of autoscaling decisions, change nothing
	$(PY) scripts/autoscale.py --compose-file compose.yaml --compose-file compose.dev.yaml --dry-run --once

lab-program:  ## create the 'local-lab' program scoped to the dev lab target
	./scripts/bootstrap.sh lab

bbctl:  ## run bbctl inside the orchestrator container: make bbctl ARGS="program list"
	./bbctl $(ARGS)

backup:  ## pg_dump the platform state to data/backups/
	./scripts/backup.sh

restore:  ## restore a backup: make restore FILE=data/backups/....dump
	./scripts/backup.sh restore $(FILE)

migrate:  ## apply database migrations
	$(COMPOSE) run --rm migrate

venv:  ## local virtualenv for tests/lint
	uv venv -q -p 3.12 .venv && uv pip install -q --python .venv/bin/python -e 'apps/orchestrator[dev]'

test:  ## unit tests
	$(PY) -m pytest -q tests/unit

test-integration:  ## integration tests against the running stack
	$(PY) -m pytest -q -m integration tests/integration

lint:  ## ruff + mypy
	$(PY) -m ruff check apps workers tests migrations scripts/autoscale.py
	$(PY) -m ruff format --check apps workers tests migrations scripts/autoscale.py
	$(PY) -m mypy

format:
	$(PY) -m ruff check --fix apps workers tests migrations scripts/autoscale.py
	$(PY) -m ruff format apps workers tests migrations scripts/autoscale.py

reset:  ## DESTRUCTIVE: remove containers AND volumes (all data)
	@read -p "This deletes all platform data (PostgreSQL, Elasticsearch, Redis). Type 'reset' to continue: " a; \
	  [ "$$a" = "reset" ] && $(DEV_COMPOSE) down -v --remove-orphans || echo aborted

clean:  ## remove local caches
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache
