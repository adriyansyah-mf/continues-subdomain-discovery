# Running Nuclei externally, reporting to the platform

The platform has a built-in nuclei worker (`workers/nuclei/`, policy `vulnerability`). This page
covers the alternative: running Nuclei yourself, only against assets you are authorised to scan
under a program you participate in. The platform gives you a scope-verified target list and ingests
the findings with its own schema, so they appear in Kibana next to the CVE/KEV data.

## 1. Get an in-scope target list

```bash
# Via the ./bbctl wrapper (runs in the container): redirect stdout to a host file.
./bbctl program targets <program> --kind url  > targets.txt     # live URLs (from httpx)
./bbctl program targets <program> --kind host > targets.txt     # domains / IPs
# A locally installed bbctl can write directly: bbctl program targets <program> --kind url --out targets.txt
```

Only assets whose program link is `in_scope`, that are not paused/retired, **and** that still pass a
fresh `ScopeEngine` check are returned. The scope guarantee stays on the platform: Nuclei can only
receive targets the platform would itself allow. (`GET /programs/{ref}/targets` is the same thing.)

## 2. Run Nuclei (pinned templates, conservative rate)

```bash
# Pin the template release; never auto-update in an operational run.
nuclei -update-templates -tv v10.4.9        # once, to fetch a known version
nuclei -l targets.txt -jsonl -silent \
  -severity medium,high,critical \
  -exclude-tags dos,fuzz,intrusive,bruteforce \
  -rl 10 -c 10 -timeout 10 \
  | ./scripts/nuclei-to-platform.sh "<program name>"
```

`-H "$BB_REQUEST_HEADER"` adds your identification header if a program requires one.

## 3. Where it lands

`scripts/nuclei-to-platform.sh` converts each Nuclei finding to the platform's unified event schema
and pushes it to the `nuclei` Logstash pipeline, so it is indexed into `bb-nuclei-*` with the same
fields the dashboards use (`nuclei.severity`, `nuclei.template_id`, `nuclei.cve_ids`, …). See the
**Vulnerability Monitoring** dashboard, panel "Nuclei findings by severity". Source is tagged
`nuclei-external`. The script needs `jq` and the running stack; it reads the Redis password from the
`redis` container, so no secret is passed on the command line.

## Alternative: Nuclei's native Elasticsearch exporter

Nuclei can write straight to Elasticsearch (as in the reference project). This bypasses the
platform's normalization, so the documents keep Nuclei's native field names and the dashboard panel
(which expects `nuclei.*`) will not populate — use the bridge above if you want the dashboards to
light up. Point the exporter at a dedicated index with the least-privilege `logstash_writer` user,
never `elastic`:

```yaml
# nuclei -l targets.txt -severity medium,high,critical -rl 10 -er es.yaml
elasticsearch:
  host: "127.0.0.1"
  port: 19200           # ES_PORT from .env
  ssl: false
  username: "logstash_writer"
  password: "<LOGSTASH_WRITER_PASSWORD from .env>"
  index-name: "bb-nuclei-manual"
```

## Built-in worker vs. external runs

Prefer the built-in worker: it re-checks scope per job and per finding, refuses hosts with URL
exclusions, pins templates, always excludes `dos`/`bruteforce`/`default-login`, and records job
provenance. External runs bypass those worker-side checks, so the safety of an external run is
your responsibility.
