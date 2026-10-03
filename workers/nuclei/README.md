# nuclei worker: not implemented (deliberate)

No adapter is shipped. The orchestrator rejects `nuclei` jobs with "not implemented"
(`app/workers/registry.py`); no placeholder pretends to scan.

What already exists, so an adapter can be added without architectural changes:

* **Policy schema:** `NucleiSettings` with severity, tags, `exclude_tags` (default: dos, fuzz,
  intrusive, bruteforce) and a validated template allow-list (relative paths only, no `..`).
* **Ingestion:** the `bb-nuclei-*` / `bb-nuclei-raw-*` index templates, the `nuclei` Logstash
  pipeline and the vulnerability-dashboard panel.
* **Correlations:** `vuln_correlations` supports `status=detected` and `source=nuclei`
  (`app/services/vuln/correlate.py::record_correlation`).

Requirements for a future adapter (see docs/scanner-workers.md "Adding a worker"):

* Pin the template release (version and SHA-256) in the image; never update templates at runtime.
* Disable out-of-band interaction and enforce the program's URL exclusions; refuse hosts where that
  is not possible.
* Re-validate every matched URL/host against scope (layer 3).
* Record the template id/version and tool version on every finding.
