# Data model

PostgreSQL schema (SQLAlchemy models in `apps/orchestrator/app/models`, migration
`migrations/versions/20261002_0001_initial_schema.py`). Enumerations are stored as strings and
validated in the application (`app/models/enums.py`).

| Table | Purpose / key fields |
|---|---|
| `programs` | id, name, slug (unique), platform, description, active, default_scan_policy_id, deleted_at (soft delete) |
| `scope_entries` | CDB rows: program_id, type (domain/wildcard/cidr/ipv4/ipv6/asn/url), value, normalized_value, mode (include/exclude), source, active. Unique (program, type, normalized_value, mode) |
| `assets` | canonical identity **unique (asset_type, normalized_value)**; status, lifecycle_stage, first/last_seen, last_scanned, last_changed, criticality (manual only), confidence_score/source/reason, tags, paused |
| `program_assets` | many-to-many asset↔program: scope_id, status (in_scope/out_of_scope/excluded/removed), scope_reason, per-program criticality and tags, first/last_seen |
| `asset_relationships` | graph edges, unique (source, target, type); confidence, source, first/last_seen, metadata |
| `asset_states` | last observed state per (asset, facet) e.g. `dns`, `http:https://host`, `tls:443`; used for change detection |
| `scan_policies` | name, description, JSON config validated by `PolicyConfig` |
| `scans` | a request: program, policy, scanners, trigger, requested_by, status |
| `scan_jobs` | one (target, scanner): status, block_reason, scope_id/scope_reason, idempotency_key (unique), priority, retries, next_attempt_at, worker_id, tool_version, config_hash, result_summary |
| `schedules` | periodic scans (seeded disabled) |
| `scanner_controls`, `maintenance_windows` | pause switches and windows |
| `notification_channels`, `notification_policies` | phase-5 config (secret *references* only) |
| `audit_events` | actor, role, action, target, program, details |
| `api_keys` | SHA-256 hashes + role |
| `cloud_ranges` | provider IP ranges (lord-alfred/ipranges): provider, organization, category (cloud/cdn/service/crawler/monitoring), cidr, region (not provided by the source), source, first/last seen, removed_at. Enrichment only |
| `kev_entries`, `epss_scores`, `cves`, `cpe_lookups`, `vuln_correlations` | vulnerability intelligence (docs/vulnerability-intel.md); correlations are unique per (asset, CVE, source) with status potential/detected and separate technology/version/CPE confidences |
| `asn_ranges` | IP range → ASN, organization, country (iptoasn.com, refreshed daily). Enrichment only; ASN never authorises an IP |
| `import_runs`, `source_records` | provenance and diffing for bulk imports (bounty-targets-data) |

## Asset identity (deduplication)

| Type | Canonical value |
|---|---|
| domain / subdomain | lowercase punycode FQDN without trailing dot (`domain` if it equals its registrable domain per the bundled public-suffix list, else `subdomain`) |
| ipv4 / ipv6 | `ipaddress` canonical form; IPv4-mapped IPv6 is stored as IPv4 |
| cidr | strict network form |
| url | normalized URL (lowercase scheme/host, default port dropped, dot-segments resolved, sorted query, no fragment); raw URL is kept in events |
| certificate | SHA-256 fingerprint |
| cve | CVE id (graph node for `AFFECTED_BY_CVE`) |
| technology | canonical technology name |
| asn | `AS<number>` |

## Lifecycle

`DISCOVERED → VALIDATED (resolves) → HTTP_PROBED → TLS_IDENTIFIED → TECH_IDENTIFIED → …`.
Workers set the stage they observed; it can move backward or forward. Observations are never
deleted from Elasticsearch (subject to ILM retention).

## Confidence

Confidence is **source-based and static** — no score is computed or learned. Table in
`app/services/assets.py::SOURCE_CONFIDENCE`:

| Source | Score | Rationale |
|---|---|---|
| manual, scope_import | 1.0 | operator-asserted |
| dns, httpx | 0.95 | directly observed resolution / response |
| bounty-targets-data, tlsx, katana | 0.9 | published scope list / presented certificate / crawled host responded |
| mapcidr | 1.0 | membership of an in-scope CIDR (a fact, not liveness) |
| certstream, bbot | 0.7 | passive or indirect |
| uncover | 0.5 | third-party index |

An asset keeps the highest-confidence explanation seen. Technology confidence and version
confidence are separate fixed values per fingerprint source (`app/services/technology.py`):
wappalyzer match 0.8 / version 0.7; `Server` header 0.9 / 0.8. Versions are only taken from tool
output, never inferred. Favicon hashes carry confidence 0.5 and are correlation hints only.

## Change detection

Pure diff functions in `app/services/changes.py` compare the previous `asset_states` row with the
new observation and emit `bb-changes-*` events (asset, program, type, previous, current,
timestamp, source, confidence). Implemented types: `DNS_CHANGED, A_CHANGED, AAAA_CHANGED,
CNAME_CHANGED, MX_CHANGED, NS_CHANGED, IP_CHANGED, NEW_IP, NEW_URL, NEW_SUBDOMAIN, NEW_DOMAIN
(import), HTTP_STATUS_CHANGED, TITLE_CHANGED, TECHNOLOGY_ADDED, TECHNOLOGY_REMOVED,
TECHNOLOGY_CHANGED, CLOUD_PROVIDER_CHANGED (CDN), NEW_CERTIFICATE, TLS_CHANGED, CERT_CHANGED,
FINGERPRINT_CHANGED, ISSUER_CHANGED, SAN_CHANGED, TLS_VERSION_CHANGED, CERT_EXPIRING,
CERTIFICATE_EXPIRED, NEW_PORT/PORT_REMOVED (function only), SCOPE_BLOCKED`. Not yet produced:
Phase 6 adds `ASN_CHANGED` (httpx/dns state carries the ASN). Phase 4 adds `NEW_CVE` and `KEV_ADDED` (per asset, from correlation). Since phase 3 also: `NEW_ENDPOINT` (katana, per origin;
first crawl is the baseline), `CLOUD_PROVIDER_CHANGED` from IP-range attribution (httpx/dns).

Each observation also emits an `ASSET_SNAPSHOT` document to `bb-assets-*`, so history is
append-only.
