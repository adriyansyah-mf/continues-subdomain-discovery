# Scanner workers

## Interface

A worker is a `ScannerAdapter` (`workers/common/adapter.py`) run by the generic `WorkerRunner`
(`workers/common/runner.py`):

```python
class ScannerAdapter(abc.ABC):
    name: str            # registry key == scanner name in jobs/policies
    queue: str           # Redis queue consumed
    tool: str
    contacts_target: bool = True   # if True the runner resolves + pins target IPs first
    def tool_version(self) -> str: ...
    def execute(self, ctx: JobContext) -> RawOutput: ...            # runs the tool, no DB access
    def process(self, session, ctx, raw) -> ScanOutcome: ...        # normalize, layer-3 check, assets, events
```

The runner owns everything else, identically for every tool: claim, scope layers 2/2b,
operational guards, policy, CIDR limits, concurrency slot, timeout/cancellation, event emission
(before commit), success/retry/DLQ, heartbeats and structured logs. Replacing httpx with another
prober means writing one adapter; nothing else changes.

Tools are executed by `workers/common/process.py::run_tool`: argv list (never a shell), own
process group, hard wall-clock timeout, output-size cap, cancellation polling (a cancelled job
kills the process). Command lines are built only from validated job/policy fields — there is no
way to pass free-form flags through the API.

## Status

| Scanner | Queue | Status | Notes |
|---|---|---|---|
| httpx | `httpx` | **implemented** | `-json -sc -title -server -ip -cname -cdn -rt -cl -location -td -favicon`, `-rl/-t/-timeout/-retries` from policy, `-allow <validated IPs>`, optional `-fhr` (same-host redirects only), never `-fr` |
| tlsx | `tlsx` | **implemented** | connects to validated IPs with `-sni <host>`; `-tv -cipher -hash sha256 -serial` |
| dns | `dns` | **implemented** | dnspython; `contacts_target=False` (talks to resolvers only) |
| certstream | (stream) | **implemented** | `workers/certstream`: long-running websocket consumer (not job-based), see below |
| mapcidr | `mapcidr` | **implemented** | expands an in-scope CIDR (bounded by `MAX_CIDR_SIZE`/`MAX_IPS_PER_JOB` before *and* during execution) into IP assets + `BELONGS_TO_CIDR` edges + `bb-ips` inventory; optional `followup_scanners` (e.g. tlsx) |
| uncover | `discovery` | **implemented** | engine-specific queries for the job's domain; in-scope results become assets (`DISCOVERED_FROM`), out-of-scope results are stored only as passive `bb-uncover` events; optional `followup_scanners` (tlsx/httpx). Needs engine API keys (`SHODAN_API_KEY`, …); without one the job fails once (non-retryable) |
| katana | `katana` | **implemented** | `-fs fqdn` (same host only), program URL exclusions → `-cos` regexes, `-dr` unless `follow_redirects`, depth ≤ `MAX_CRAWL_DEPTH`, output capped at `MAX_URLS_PER_CRAWL` (tool stopped), every URL re-checked; `bb-katana`, `bb-katana-raw`, `bb-urls` (doc id = url hash), `NEW_ENDPOINT` changes, host lifecycle `CRAWLED` |
| nuclei | `nuclei` | **implemented** | templates cloned + commit-verified into the image (release marker cross-checked at runtime, `-duc`), OOB disabled (`-ni`, OAST templates excluded), `-or -ot` output without request/response bodies, severity/tags/template allow-list from the policy, intrusive tags excluded by default; a host with any URL exclusion is refused (nuclei cannot constrain paths), every matched URL re-checked (layer 3) → `bb-nuclei` / `bb-nuclei-raw`, `NEW_FINDING` / `NEW_CRITICAL_FINDING` / `FINDING_RESOLVED` changes, CVE-classified findings become `vuln_correlations(status=detected, source=nuclei)` |
| bbot | `bbot` | **implemented** | own image (`workers/bbot/Dockerfile`, BBOT 3.0.2 in an isolated venv). `subdomain-enum` preset with `-rf passive safe` by default (nothing sent to the target), program exclusions as BBOT blacklist, `crt_db` excluded. Every DNS_NAME/IP is re-checked by the ScopeEngine: in-scope → assets (`DISCOVERED_FROM`, `RESOLVES_TO`), ASN → `BELONGS_TO_ASN`, CPE technologies → `USES_TECHNOLOGY`, passive open ports → `NEW_PORT`/`PORT_REMOVED`; everything else stays in `bb-bbot-*`. `speculate` events are ignored. BBOT exits 0 on config errors, so a run without a final SCAN event fails the job |
| asn | (scheduler) | **implemented** | iptoasn.com ranges synced daily (`ASN_SYNC_INTERVAL`) or `bbctl sync asn`; every IP the workers see gets `asn.*` and a `BELONGS_TO_ASN` edge; `ASN_CHANGED` from httpx/dns state |
| ipranges | (scheduler) | **implemented** | lord-alfred/ipranges synced daily by the scheduler (`IPRANGES_SYNC_INTERVAL`) or `bbctl sync ipranges`; used to enrich IPs (`cloud.*`, `cloud:<provider>` asset tags, `CLOUD_PROVIDER_CHANGED`) — never scope |
| cve-monitor | `cve` | **implemented** | KEV / EPSS feeds + NVD CPE→CVE correlation; never scans (docs/vulnerability-intel.md) |

Requesting an unimplemented scanner returns HTTP 422 with an explicit message.

## CertStream

`workers/certstream/service.py` connects to `CERTSTREAM_URL` (calidog certstream or a
self-hosted certstream-server-go; both message formats are parsed) with automatic reconnect and
exponential backoff with jitter (1 s → 5 min). Per certificate:

1. parse CN/SAN/issuer/serial/fingerprints/validity (`parser.py`); names are normalized, wildcard
   SANs are recorded but never become assets, invalid names are dropped;
2. every name is evaluated against **all** programs with `CachedScopeEngine` (30 s TTL; an
   unloadable scope means nothing is recorded);
3. no match → dropped, or stored in `bb-certstream-*` with `scope.status: out` when
   `CERTSTREAM_STORE_OUT_OF_SCOPE=true`;
4. match → dedup by fingerprint (Redis, `CERTSTREAM_DEDUP_TTL`), certificate asset + domain
   assets (confidence 0.7, reason `certificate SAN matched <rule>`), program links,
   `DISCOVERED_FROM` edges, `NEW_DOMAIN`/`NEW_SUBDOMAIN`/`NEW_CERTIFICATE` changes, one
   `CT_CERTIFICATE` event per program;
4b. names on every certificate are flagged with "interesting domain" heuristics
   (`certstream.flags`: `suspicious_tld` for free/abused TLDs, `numeric` for digit-leading labels,
   `punycode` for `xn--`/IDN), mirroring the reference project's buckets. Shown on the Certificate
   Monitoring dashboard; with `CERTSTREAM_STORE_OUT_OF_SCOPE=true` you can watch the whole CT stream.
5. follow-up jobs (`CERTSTREAM_FOLLOWUP_SCANNERS`, default `dns`) only for **newly created**
   assets of **active** programs, created through `ScanService`, so all scope/policy/pause checks
   apply again.

A stream that sends nothing (not even heartbeats) for `CERTSTREAM_IDLE_TIMEOUT` seconds (default
300) is treated as dead and reconnected; `bbctl worker status` shows `messages`, `certificates`,
`in_scope`, `duplicates`, `disconnects` and `idle_reconnects` counters. As of 2026-10 the public
`wss://certstream.calidog.io` accepted connections but delivered no messages, so the compose file
ships an optional self-hosted **certstream-server-go** (`configs/certstream/config.yaml`, no
backfill, internal network only):

```bash
# .env
COMPOSE_PROFILES=ct-server
CERTSTREAM_URL=ws://certstream-server:8080/
```

Certificate asset identity is the SHA-256 fingerprint when the stream provides it
(certstream-server-go), otherwise `sha1:<hex>` (calidog only publishes SHA-1); tlsx observations
use SHA-256, so calidog-sourced certificates do not merge with tlsx ones.

## Follow-up jobs

Discovery workers (mapcidr, uncover) can queue further scanners for what they found
(`followup_scanners` in the policy, limited to dns/httpx/tlsx). Follow-ups are created through
`ScanService` with the parent job's program and policy, so scope, pause, maintenance, policy and
limits are all re-checked, and they are enqueued only after the parent job's transaction commits
(`ScanOutcome.followup_job_ids`). `scans.trigger` records the provenance (`mapcidr:<job id>`).

## Error classes

Tool failures and timeouts are retried with exponential backoff; `NonRetryableError` (e.g. no API
key for any uncover engine) fails the job immediately and dead-letters it.

## Image

`workers/common/Dockerfile`: stage 1 downloads pinned ProjectDiscovery release zips and verifies
them against the release checksum file (`scripts/install-tools.sh`); stage 1b clones the pinned
nuclei-templates tag and verifies it against a pinned commit SHA
(`scripts/install-nuclei-templates.sh`); stage 2 is `python:3.12.14-slim-bookworm` with the
platform package. Bundled binaries: httpx 1.12.0, tlsx 1.4.0, mapcidr 1.1.97, katana 1.7.0,
uncover 1.2.1, nuclei 3.11.1, plus nuclei-templates v10.4.9 in `/opt/pd/nuclei-templates`
(read-only, with a release marker the adapter cross-checks). Binaries live in `/opt/pd/bin`
because the Python `httpx` library installs an unrelated `httpx` console script. Containers run
as uid 10001, read-only root, `cap_drop: ALL`, `no-new-privileges`, `HOME=/tmp` (tmpfs).

## Adding a worker

1. `workers/<name>/adapter.py` implementing `ScannerAdapter`; `workers/<name>/__main__.py`.
2. Set `implemented=True` in `app/workers/registry.py`.
3. Add settings to `PolicyConfig` if needed.
4. Emit only to indices allowed for its pipeline (`PIPELINE_INDICES` + `logstash/pipelines/<x>.conf`).
5. Add a compose service using the `*worker` anchor; add unit tests with recorded tool output.
