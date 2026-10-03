# Scan policies

Stored in `scan_policies` (PostgreSQL) as JSON validated by `app/schemas/policy.py::PolicyConfig`
(`extra="forbid"`: unknown keys — including any attempt to pass raw CLI flags — are rejected).

Per scanner: `enabled`, `rate_limit` (req/s), `concurrency`, `timeout`, `retries`,
`max_duration`, `time_bucket_seconds` (idempotency window). Scanner-specific:

* httpx: `ports`, `follow_host_redirects`, `tech_detect`, `favicon`
* tlsx: `ports`
* dns: `record_types`, `resolvers`
* katana: `depth`, `js_crawl`, `jsluice`, `max_urls`, `known_files`
* nuclei: `severity`, `tags`, `exclude_tags`, `templates` (ids/relative paths, no `..`)
* mapcidr: `skip_base_broadcast`, `followup_scanners`
* uncover: `engines`, `limit`, `followup_scanners`
* bbot: `preset` (subdomain-enum), `passive_only` (default true), `exclude_modules`

`followup_scanners` may only name dns, httpx or tlsx.

Every policy is also checked against deployment caps (`HTTPX_RATE_LIMIT`, `MAX_CONCURRENCY`,
`MAX_SCAN_DURATION`, `MAX_CRAWL_DEPTH`, `MAX_URLS_PER_CRAWL`, …); violations → HTTP 422.

## Seeded policies

| Name | Enabled scanners |
|---|---|
| `passive` | dns |
| `discovery` | dns, httpx (10 rps, 2 threads), tlsx |
| `conservative-web` | dns, httpx (20 rps), tlsx, katana depth 3 |
| `recon` | dns, httpx, tlsx, mapcidr (→ tlsx), uncover (→ tlsx, httpx), katana depth 2, passive BBOT |
| `crawl` | katana |
| `vulnerability` | nuclei medium/high/critical, intrusive tags excluded, daily bucket |
| `full` | all of the above |

Seeding only creates missing policies; it never overwrites an existing one (operators may have
edited it). New defaults in a release are applied with `bbctl policy update`.

A program's `default_scan_policy_id` is used when a scan names no policy; the fallback is
`passive`. A scanner disabled in the policy yields `BLOCKED / POLICY_DISABLED` jobs.

## Idempotency

`idempotency_key = sha256(program | target | scanner | policy | floor(now / time_bucket_seconds))`
(unique column). Re-submitting inside the bucket returns the existing job as a duplicate;
`force: true` (`bbctl scan run --force`) adds a nonce. Blocked/out-of-scope jobs get random keys
so they never suppress a later legitimate run.

## Schedules

`schedules` rows (seeded **disabled**): `dns-periodic` (6h), `httpx-periodic` (24h),
`tlsx-periodic` (24h). Enable with `bbctl schedule enable httpx-periodic [--program x] [--policy y]`.
When due, the scheduler creates one scan per active program over its in-scope assets of the
scanner's target types (capped by `MAX_TARGETS_PER_SCAN`).
