#!/usr/bin/env python3
"""Generate Kibana dashboards (saved objects NDJSON) for the platform.

Dashboards are defined as code here and written to kibana/dashboards/*.ndjson,
which scripts/bootstrap-kibana.sh imports. Re-run after editing:

    python3 kibana/build_dashboards.py

Uses aggregation-based visualizations (metric / pie / table / markdown) because
their saved-object format is compact and stable across 8.x minor versions.
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).parent / "dashboards"
KIBANA_VERSION = "8.19.22"


def _search_source(query: str = "") -> dict:
    return {
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    }


def _vis(vid: str, title: str, data_view: str, vis_type: str, aggs: list, params: dict, query: str = "") -> dict:
    return {
        "type": "visualization",
        "id": vid,
        "attributes": {
            "title": title,
            "visState": json.dumps({"title": title, "type": vis_type, "aggs": aggs, "params": params}),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(_search_source(query))},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": data_view}
        ],
    }


def _count(aid: str = "1") -> dict:
    return {"id": aid, "enabled": True, "type": "count", "params": {}, "schema": "metric"}


def _terms(aid: str, field: str, schema: str, size: int = 10) -> dict:
    return {
        "id": aid,
        "enabled": True,
        "type": "terms",
        "params": {
            "field": field,
            "size": size,
            "order": "desc",
            "orderBy": "1",
            "missingBucket": False,
            "otherBucket": False,
        },
        "schema": schema,
    }


def metric(vid, title, dv, query="", unique_field: str | None = None, label: str | None = None):
    agg = (
        {
            "id": "1",
            "enabled": True,
            "type": "cardinality",
            "params": {"field": unique_field, "customLabel": label},
            "schema": "metric",
        }
        if unique_field
        else {"id": "1", "enabled": True, "type": "count", "params": {"customLabel": label}, "schema": "metric"}
    )
    return _vis(
        vid,
        title,
        dv,
        "metric",
        [agg],
        {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {"bgFill": "#000", "bgColor": False, "labelColor": False, "subText": "", "fontSize": 48},
            },
        },
        query,
    )


def pie(vid, title, dv, field, query="", size=10):
    return _vis(
        vid,
        title,
        dv,
        "pie",
        [_count(), _terms("2", field, "segment", size)],
        {
            "type": "pie",
            "addTooltip": True,
            "legendDisplay": "show",
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        },
        query,
    )


def table(vid, title, dv, fields: list[str], query="", size=20, extra_metric: dict | None = None):
    aggs = [_count()] if extra_metric is None else [extra_metric]
    aggs += [_terms(str(i + 2), f, "bucket", size) for i, f in enumerate(fields)]
    return _vis(
        vid,
        title,
        dv,
        "table",
        aggs,
        {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
        },
        query,
    )


def timeseries(vid, title, dv, query="", split_field: str | None = None, split_size: int = 8):
    """Line chart of document counts over @timestamp (optionally split into series by a field)."""
    aggs = [
        _count(),
        {
            "id": "2",
            "enabled": True,
            "type": "date_histogram",
            "schema": "segment",
            "params": {"field": "@timestamp", "interval": "auto", "min_doc_count": 1, "extended_bounds": {}},
        },
    ]
    if split_field:
        aggs.append(_terms("3", split_field, "group", split_size))
    params = {
        "type": "line",
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "bottom",
                "show": True,
                "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100},
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "left",
                "show": True,
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": "line",
                "mode": "normal",
                "data": {"label": "Count", "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "interpolate": "linear",
                "showCircles": True,
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
        "labels": {},
        "thresholdLines": {"show": False, "value": 10, "width": 1, "style": "full", "color": "#E7664C"},
    }
    return _vis(vid, title, dv, "line", aggs, params, query)


def markdown(vid, title, text):
    return {
        "type": "visualization",
        "id": vid,
        "attributes": {
            "title": title,
            "visState": json.dumps(
                {
                    "title": title,
                    "type": "markdown",
                    "aggs": [],
                    "params": {"markdown": text, "fontSize": 12, "openLinksInNewTab": False},
                }
            ),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": [],
    }


def dashboard(did: str, title: str, description: str, vis: list[dict], width: int = 16) -> list[dict]:
    panels, refs = [], []
    x = y = 0
    for i, v in enumerate(vis):
        vtype = json.loads(v["attributes"]["visState"])["type"]
        w = 48 if vtype in ("markdown", "line") else (24 if vtype == "table" else width)
        h = 4 if vtype == "markdown" else (7 if vtype == "metric" else 13)
        if x + w > 48:
            x, y = 0, y + 13
        panels.append(
            {
                "version": KIBANA_VERSION,
                "type": "visualization",
                "panelIndex": str(i + 1),
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                "embeddableConfig": {},
                "panelRefName": f"panel_{i + 1}",
            }
        )
        refs.append({"name": f"panel_{i + 1}", "type": "visualization", "id": v["id"]})
        x += w
        if vtype == "markdown":
            x, y = 0, y + h
    dash = {
        "type": "dashboard",
        "id": did,
        "attributes": {
            "title": title,
            "description": description,
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeFrom": "now-30d",
            "timeTo": "now",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
            },
        },
        "references": refs,
    }
    return [*vis, dash]


CERT_TYPES = (
    "NEW_CERTIFICATE or CERT_CHANGED or FINGERPRINT_CHANGED or SAN_CHANGED or ISSUER_CHANGED "
    "or TLS_VERSION_CHANGED or CERT_EXPIRING or CERTIFICATE_EXPIRED or TLS_CHANGED"
)

DASHBOARDS = {
    "attack-surface-overview": dashboard(
        "bb-dash-overview",
        "Attack Surface Overview",
        "Inventory snapshot across all programs. Canonical inventory lives in PostgreSQL; this is the event view.",
        [
            metric("ov-assets", "Assets (unique)", "bb-assets", unique_field="asset.id", label="assets"),
            metric(
                "ov-subdomains",
                "Domains & subdomains",
                "bb-assets",
                'asset.type:("domain" or "subdomain")',
                unique_field="asset.id",
                label="domains",
            ),
            metric("ov-urls", "Live URLs (HTTP)", "bb-http", unique_field="url.full", label="urls"),
            metric(
                "ov-new24",
                "New assets (24h)",
                "bb-changes",
                'event.type:(NEW_DOMAIN or NEW_SUBDOMAIN or NEW_IP or NEW_URL) and @timestamp >= "now-24h"',
                label="new",
            ),
            metric(
                "ov-changed24",
                "Changed assets (24h)",
                "bb-changes",
                '@timestamp >= "now-24h"',
                unique_field="asset.id",
                label="changed",
            ),
            pie("ov-types", "Asset types", "bb-assets", "asset.type"),
            pie("ov-tech", "Technologies", "bb-http", "technology.name", size=15),
            pie("ov-status", "HTTP status", "bb-http", "http.response.status_code"),
            pie("ov-cdn", "CDN / WAF", "bb-http", "http.cdn.name"),
            pie("ov-asn", "ASN distribution", "bb-all", "asn.number"),
            pie("ov-cloud", "Cloud / provider (ipranges)", "bb-all", "cloud.provider"),
            table("ov-programs", "Observations by program", "bb-all", ["program.name", "bb.index"]),
            timeseries(
                "ov-ts-new",
                "New assets over time",
                "bb-changes",
                "event.type:(NEW_DOMAIN or NEW_SUBDOMAIN or NEW_IP or NEW_URL or NEW_CERTIFICATE)",
                split_field="event.type",
            ),
        ],
    ),
    "certificate-monitoring": dashboard(
        "bb-dash-certs",
        "Certificate Monitoring",
        "TLS observations from tlsx and certificate change events.",
        [
            metric("ct-certs", "Certificates seen", "bb-tls", unique_field="tls.fingerprint", label="certificates"),
            metric("ct-new", "New certificates", "bb-changes", "event.type:NEW_CERTIFICATE", label="new"),
            metric(
                "ct-expiring",
                "Expiring (<=30d)",
                "bb-tls",
                "tls.expiry_status:expiring",
                unique_field="tls.fingerprint",
                label="expiring",
            ),
            metric(
                "ct-expired",
                "Expired",
                "bb-tls",
                "tls.expiry_status:expired",
                unique_field="tls.fingerprint",
                label="expired",
            ),
            pie("ct-issuer", "Issuers", "bb-tls", "tls.issuer_cn"),
            pie("ct-version", "TLS versions", "bb-tls", "tls.version"),
            pie("ct-cipher", "Ciphers", "bb-tls", "tls.cipher"),
            table(
                "ct-changes",
                "Certificate changes",
                "bb-changes",
                ["asset.value", "event.type"],
                f"event.type:({CERT_TYPES})",
            ),
            table(
                "ct-exp-table",
                "Expiring / expired certificates",
                "bb-tls",
                ["asset.value", "tls.not_after", "tls.expiry_status"],
                "tls.expiry_status:(expiring or expired)",
            ),
            metric(
                "ct-interesting",
                "Interesting CT domains",
                "bb-certstream",
                "certstream.interesting:true",
                unique_field="asset.value",
                label="flagged",
            ),
            pie(
                "ct-flags",
                "CT domain flags (suspicious TLD / numeric / punycode)",
                "bb-certstream",
                "certstream.flags",
                "certstream.interesting:true",
            ),
            table(
                "ct-interesting-table",
                "Interesting domains from Certificate Transparency",
                "bb-certstream",
                ["asset.value", "certstream.flags"],
                "certstream.interesting:true",
                size=50,
            ),
        ],
    ),
    "web-technology": dashboard(
        "bb-dash-web",
        "Web Technology",
        "httpx fingerprints (technology confidence and version confidence are "
        "separate fields; versions are never inferred).",
        [
            pie("wt-tech", "Technologies", "bb-http", "technology.name", size=20),
            pie("wt-server", "Web servers", "bb-http", "http.webserver"),
            pie("wt-status", "HTTP status", "bb-http", "http.response.status_code"),
            table(
                "wt-versions",
                "Technology versions",
                "bb-http",
                ["technology.name", "technology.version"],
                "technology.version:*",
            ),
            table("wt-titles", "Page titles", "bb-http", ["http.title.keyword", "url.domain"]),
            table(
                "wt-favicon",
                "Favicon hash correlation (not proof of ownership)",
                "bb-http",
                ["http.favicon.mmh3", "url.domain"],
                "http.favicon.mmh3:*",
            ),
            table(
                "wt-cdn",
                "CDN / WAF by host",
                "bb-http",
                ["http.cdn.name", "http.cdn.type", "url.domain"],
                "http.cdn.detected:true",
            ),
        ],
    ),
    "vulnerability-monitoring": dashboard(
        "bb-dash-vuln",
        "Vulnerability Monitoring",
        "CVE correlations (asset -> technology -> version -> CPE -> NVD), CISA KEV and EPSS side by side. "
        "No composite risk score is computed.",
        [
            markdown(
                "vu-note",
                "How to read this",
                "**potential** = the fingerprinted product *version* matches an NVD CPE configuration; it is "
                "not proof the asset is vulnerable (see `cve.cpe_confidence_level`, "
                "`technology.version_confidence`). **detected** = confirmed by a scanner template "
                "(nuclei worker: not implemented yet). CVSS, EPSS and KEV are independent signals.",
            ),
            metric("vu-corr", "Asset/CVE correlations", "bb-cve", label="correlations"),
            metric("vu-assets", "Affected assets", "bb-cve", unique_field="asset.id", label="assets"),
            metric(
                "vu-kev-hits",
                "Correlated CVEs in KEV",
                "bb-cve",
                "kev.in_catalog:true",
                unique_field="cve.id",
                label="kev",
            ),
            metric(
                "vu-kev-total",
                "KEV catalogue entries",
                "bb-kev",
                "kev.in_catalog:true",
                unique_field="cve.id",
                label="kev entries",
            ),
            pie("vu-status", "Correlation status", "bb-cve", "vulnerability.status"),
            pie("vu-sev", "CVSS severity", "bb-cve", "cvss.severity"),
            pie("vu-cpe-conf", "CPE mapping confidence", "bb-cve", "cve.cpe_confidence_level"),
            table(
                "vu-assets-table",
                "Affected assets (asset / CVE / technology version)",
                "bb-cve",
                ["asset.value", "cve.id", "technology.version"],
                size=50,
            ),
            table(
                "vu-epss",
                "Highest EPSS among correlated CVEs",
                "bb-cve",
                ["cve.id"],
                extra_metric={
                    "id": "1",
                    "enabled": True,
                    "type": "max",
                    "params": {"field": "epss.score"},
                    "schema": "metric",
                },
            ),
            table("vu-kev-vendors", "KEV catalogue by vendor", "bb-kev", ["kev.vendor"], "kev.in_catalog:true"),
            table(
                "vu-kev-changes",
                "KEV changes",
                "bb-kev",
                ["event.type", "cve.id"],
                "event.type:(KEV_ADDED or KEV_UPDATED or KEV_REMOVED)",
            ),
            pie(
                "vu-nuclei-sev", "Nuclei findings by severity (worker not implemented)", "bb-nuclei", "nuclei.severity"
            ),
        ],
    ),
    "attack-surface-changes": dashboard(
        "bb-dash-changes",
        "Attack Surface Changes",
        "All change events (bb-changes-*), including SCOPE_BLOCKED.",
        [
            metric("ch-total", "Changes", "bb-changes", "not event.type:SCOPE_BLOCKED", label="changes"),
            metric("ch-blocked", "Scope blocked", "bb-changes", "event.type:SCOPE_BLOCKED", label="blocked"),
            timeseries(
                "ch-ts",
                "Changes over time by type",
                "bb-changes",
                "not event.type:SCOPE_BLOCKED",
                split_field="event.type",
            ),
            pie("ch-types", "Change types", "bb-changes", "event.type", size=25),
            pie("ch-programs", "Changes by program", "bb-changes", "program.name"),
            table(
                "ch-recent",
                "Changes by asset",
                "bb-changes",
                ["asset.value", "event.type", "change.current"],
                "not event.type:SCOPE_BLOCKED",
                size=50,
            ),
            table(
                "ch-scope",
                "Scope blocks (target / layer / reason)",
                "bb-changes",
                ["asset.value", "scope_check.layer", "scope_check.reason.keyword"],
                "event.type:SCOPE_BLOCKED",
            ),
        ],
    ),
    "recon-discovery": dashboard(
        "bb-dash-recon",
        "Recon Discovery",
        "Crawling (katana), passive discovery (BBOT, uncover) and IP inventory (mapcidr) with provider attribution.",
        [
            metric("rc-urls", "URLs inventoried", "bb-urls", unique_field="url.hash", label="urls"),
            metric("rc-endpoints", "Endpoints", "bb-urls", unique_field="url.endpoint_hash", label="endpoints"),
            metric(
                "rc-js", "JS-discovered URLs", "bb-urls", "url.js_discovered:true", unique_field="url.hash", label="js"
            ),
            metric("rc-ips", "IP inventory", "bb-ips", unique_field="host.ip", label="ips"),
            pie("rc-bbot-types", "BBOT event types", "bb-bbot", "bbot.type", "not bbot.type:SCAN", size=15),
            pie("rc-bbot-modules", "BBOT modules", "bb-bbot", "bbot.module", size=15),
            pie("rc-cloud", "IPs by provider", "bb-ips", "cloud.provider"),
            table("rc-endpoints-host", "Endpoints by host", "bb-urls", ["url.domain", "url.path"], size=50),
            table(
                "rc-uncover",
                "uncover results (engine / scope)",
                "bb-uncover",
                ["uncover.engine", "scope_check.allowed", "asset.value"],
            ),
            table(
                "rc-new",
                "New endpoints / ports",
                "bb-changes",
                ["asset.value", "event.type", "change.current"],
                "event.type:(NEW_ENDPOINT or NEW_PORT or PORT_REMOVED)",
            ),
        ],
    ),
    "recon-operations": dashboard(
        "bb-dash-ops",
        "Recon Operations",
        "Jobs, queues, workers and errors. Job docs are current-state (one doc per job id).",
        [
            metric("op-jobs", "Jobs", "bb-jobs", "event.category:job", label="jobs"),
            metric("op-running", "Running", "bb-jobs", "job.status:RUNNING", label="running"),
            metric("op-failed", "Failed", "bb-jobs", "job.status:FAILED", label="failed"),
            metric(
                "op-blocked",
                "Blocked / out of scope",
                "bb-jobs",
                "job.status:(BLOCKED or OUT_OF_SCOPE)",
                label="blocked",
            ),
            metric("op-dlq", "DLQ events", "bb-errors", "event.type:DLQ_EVENT", label="dlq"),
            timeseries(
                "op-ts-jobs", "Jobs over time by status", "bb-jobs", "event.category:job", split_field="job.status"
            ),
            pie("op-status", "Jobs by status", "bb-jobs", "job.status", "event.category:job"),
            pie("op-scanner", "Jobs by scanner", "bb-jobs", "job.scanner", "event.category:job"),
            pie("op-block", "Block reasons", "bb-jobs", "job.block_reason", "job.block_reason:*"),
            table(
                "op-duration",
                "Average duration by scanner (s)",
                "bb-jobs",
                ["job.scanner"],
                "job.status:SUCCESS",
                extra_metric={
                    "id": "1",
                    "enabled": True,
                    "type": "avg",
                    "params": {"field": "job.duration_seconds"},
                    "schema": "metric",
                },
            ),
            table(
                "op-queue",
                "Queue depth (max pending)",
                "bb-jobs",
                ["queue.name"],
                "event.type:QUEUE_DEPTH",
                extra_metric={
                    "id": "1",
                    "enabled": True,
                    "type": "max",
                    "params": {"field": "queue.pending"},
                    "schema": "metric",
                },
            ),
            table("op-errors", "Errors by type / scanner", "bb-errors", ["error.type", "scan.tool"]),
            pie("op-notify-status", "Notifications by status", "bb-notifications", "notification.status"),
            timeseries("op-ts-notify", "Notifications over time", "bb-notifications", split_field="notification.type"),
            table(
                "op-notify-types",
                "Notifications by type / channel",
                "bb-notifications",
                ["notification.type", "notification.channel", "notification.status"],
            ),
        ],
    ),
}


def main() -> None:
    OUT.mkdir(exist_ok=True)
    for name, objects in DASHBOARDS.items():
        path = OUT / f"{name}.ndjson"
        path.write_text("".join(json.dumps(o, separators=(",", ":")) + "\n" for o in objects))
        print(f"wrote {path} ({len(objects)} objects)")


if __name__ == "__main__":
    main()
