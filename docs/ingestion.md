# Ingestion

## Event schema

All producers build events with `app/services/events.py::build_event`:

```json
{
  "@timestamp": "...Z",
  "event":   {"kind": "event|state|alert|metric", "category": "...", "type": "HTTP_OBSERVATION", "action": "..."},
  "bb":      {"index": "bb-http", "doc_id": "<optional upsert id>", "schema_version": "1"},
  "program": {"id": "...", "name": "..."},
  "scope":   {"id": "...", "status": "in|out|excluded"},
  "asset":   {"id": "...", "type": "...", "value": "..."},
  "scan":    {"id": "...", "job_id": "...", "tool": "httpx", "tool_version": "1.12.0", "config_hash": "..."},
  "source":  {"name": "httpx", "type": "active|passive|import|system|audit"}
}
```

plus type-specific ECS-style sections (`http`, `url`, `tls`, `dns`, `technology`, `change`,
`job`, `error`, …). This provenance answers "why is this asset in scope?": scope.id points to the
exact CDB row, scan.job_id to the job, which records the scope reason.

## Transport

`EventEmitter` RPUSHes JSON onto `bb:events:<pipeline>` (Redis). It refuses events whose
`bb.index` is not owned by that pipeline and raises when the backlog exceeds `MAX_EVENT_BACKLOG`
(the job then retries rather than dropping change events). Workers emit before committing.

Filebeat is not used: direct ingestion through Redis avoids filesystem coupling and gives
buffering during Logstash/Elasticsearch outages. `configs/filebeat/` documents how to add it for
an external JSONL-producing tool if ever needed.

## Logstash

`logstash/pipelines.yml` defines one pipeline per stream — `assets, certstream, tlsx, httpx, dns,
katana, nuclei, bbot, cve, changes, ops` — plus `dlq`. Each pipeline:

1. reads its Redis list with the json codec (parse);
2. malformed JSON / bad timestamps → `bb-errors` (`MALFORMED_EVENT`);
3. missing `bb.index`/`event.type`/`event.kind` → `bb-errors` (`MISSING_REQUIRED_FIELD`);
4. `bb.index` not owned by the pipeline → `bb-errors` (`INDEX_NOT_ALLOWED`);
5. adds `event.ingested` and `event.pipeline`;
6. writes to `<bb.index>-YYYY.MM` (with `document_id` when `bb.doc_id` is set, e.g. job state);
7. documents Elasticsearch rejects go to the Logstash DLQ, re-indexed by the `dlq` pipeline into
   `bb-errors` with the rejection reason.

Pipelines are generated identically (only the Redis key and index allow-list differ). Allow-lists
use an anchored regex; Logstash treats a one-element `in ["x"]` list as a string, which silently
broke routing during development.

## Elasticsearch

* Component template `bb-base` (`elasticsearch/mappings/bb-base.json`): explicit mappings for all
  schema fields, `dynamic: false` (unknown fields stay in `_source` but are not indexed, so no
  mapping explosion). Raw tool output is stored under `raw` as `flattened`.
* Index templates (`elasticsearch/templates/`): `bb-assets, bb-domains, bb-ips, bb-urls, bb-http,
  bb-tls, bb-dns, bb-certstream, bb-bbot, bb-katana, bb-nuclei, bb-cve, bb-kev, bb-changes,
  bb-audit, bb-scans, bb-jobs, bb-errors` and `bb-raw` (priority 300) for
  `bb-{httpx,tlsx,katana,nuclei,bbot}-raw-*`.
* ILM (`elasticsearch/ilm/`): `bb-raw-30d`, `bb-certstream-60d`, `bb-medium-90d` (http/tls/dns/
  urls/katana/bbot/jobs/errors), `bb-long-730d` (assets, changes, audit, nuclei, cve, kev).
  Indices are monthly, so data is deleted between N and N+31 days.
* Users created by `es-setup`: `logstash_writer` (create/index on `bb-*` only), `bb_monitor`
  (read `bb-*`, used by the orchestrator readiness check), `kibana_system` password.

Discovery workers also write `bb-uncover-*` / `bb-uncover-raw-*` (assets pipeline) and
`bb-katana-*`, `bb-katana-raw-*`, `bb-urls-*` (katana pipeline).

`cve-monitor` writes `bb-kev-*` (doc id = CVE) and `bb-cve-*` (one current-state doc per
asset/CVE/source/program) through the `cve` pipeline.

Currently populated indices: `bb-assets, bb-audit, bb-changes, bb-dns, bb-errors, bb-http,
bb-httpx-raw, bb-jobs, bb-tls, bb-tlsx-raw`.
