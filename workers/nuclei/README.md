# nuclei worker

Adapter: `adapter.py` (`NucleiAdapter`, queue `nuclei`), generic runner like every other scanner.
Findings go to `bb-nuclei-*` (one event per finding, `nuclei.*` fields) and `bb-nuclei-raw-*`
(verbatim JSONL); the Kibana `bb-nuclei` data view and the vulnerability dashboard's severity
panel are pre-provisioned.

## Safety model

* **Templates are image content, never runtime state.** `scripts/install-nuclei-templates.sh`
  clones the repo at a pinned tag and verifies the checkout against a pinned commit SHA
  (`NUCLEI_TEMPLATES_VERSION` / `NUCLEI_TEMPLATES_COMMIT`; the release archives are not attached
  to the GitHub releases, so tag→commit is the verifiable pin). The image writes a release
  marker that the adapter cross-checks at every job — a mismatch fails the job (non-retryable).
  `-duc` disables update checks; the read-only image layer makes runtime template changes
  impossible.
* **No out-of-band testing.** `-ni` disables interactsh entirely and excludes OAST templates, so
  no target data leaves the deployment to a third-party OOB server.
* **URL exclusions are enforced by refusal.** nuclei requests arbitrary paths on a target and
  has no path-level exclusion mechanism, so if the program has any URL exclusion for the target
  host the job is blocked (`EXCLUDED`) instead of risking a request to an excluded path.
* **Everything else is policy-driven.** severity filter (default `medium,high,critical`), tags,
  `exclude_tags` (default `dos,fuzz,intrusive,bruteforce`) and a validated template allow-list
  come from `NucleiSettings` (relative paths / template ids; the two styles cannot be mixed —
  nuclei selects them by different mechanisms); rate limit, concurrency, timeout and retries
  are bounded by the policy and the deployment caps. Command lines are built from validated
  fields only — no free-form flags through the API.
* **Layer 3 re-validation.** every finding's `matched-at` URL is re-checked against fresh scope
  before it is stored; blocked findings are dropped and reported as `SCOPE_BLOCKED`.
* **No response bodies in events.** `-or -ot` omit request/response pairs and the encoded
  template from the JSONL; the curl command and extractor results are kept as evidence.
* Like katana, nuclei resolves DNS itself, so rebinding protection relies on the runner's
  pre-flight resolution check plus output validation (IPs cannot be pinned for this tool).

## Correlations and changes

Findings whose template `info.classification` carries CVE ids upgrade the matching
`vuln_correlations` rows to `status=detected, source=nuclei` (evidence: template id, matched
URL, finding hash; capped at 100 per job). Per host, finding sets are diffed against the last
scan (`vulnscan:<host>` asset state): first scan is a baseline; afterwards `NEW_FINDING`,
`FINDING_RESOLVED` and — for new criticals — `NEW_CRITICAL_FINDING` (notifiable) are raised.
The host asset moves to lifecycle stage `VULN_SCANNED`.

## Updating

Bump `NUCLEI_VERSION`, `NUCLEI_TEMPLATES_VERSION` and `NUCLEI_TEMPLATES_COMMIT` (from
`https://api.github.com/repos/projectdiscovery/nuclei-templates/git/ref/tags/<tag>`) in
`.env.example`, rebuild the image, and run the worker tests. Never point the worker at a
mutable templates directory.

## Running Nuclei externally today

Until an adapter exists, external Nuclei integrates cleanly without the platform launching it:
`bbctl program targets <program>` gives a scope-verified target list, and
`scripts/nuclei-to-platform.sh` ingests findings into `bb-nuclei-*` with the platform schema so the
dashboards populate. See [docs/nuclei-external.md](../../docs/nuclei-external.md).
