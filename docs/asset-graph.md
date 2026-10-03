# Asset graph

Edges live in `asset_relationships` (PostgreSQL), unique per (source, target, type), with
`confidence`, `source`, `first_seen`, `last_seen`, `metadata`.
Query: `GET /assets/{id}/relationships`, `bbctl asset show <id>`.

## Edges produced today

| Edge | Producer | Notes |
|---|---|---|
| domain `RESOLVES_TO` ip | dns, httpx | metadata.record_type = A/AAAA |
| domain `CNAME_TO` domain | dns | |
| domain `USES_NAMESERVER` domain | dns | |
| domain `USES_MAIL_SERVER` domain | dns | |
| domain `HAS_URL` url | httpx | |
| url `USES_TECHNOLOGY` technology | httpx | metadata.version / version_confidence |
| host `USES_CERTIFICATE` certificate | tlsx | metadata.port / ip |
| domain `DISCOVERED_FROM` certificate | tlsx, certstream | only for SANs inside a program's scope |
| asset `DISCOVERED_FROM` job asset | uncover, BBOT | metadata: engine / module |
| host `USES_TECHNOLOGY` technology | BBOT | metadata: version, cpe (passive third-party data) |
| ip `BELONGS_TO_CIDR` cidr | mapcidr | |
| ip `BELONGS_TO_ASN` asn | iptoasn enrichment (httpx, dns, mapcidr, uncover, BBOT) | metadata: organization, country |
| asset `AFFECTED_BY_CVE` cve | cve-monitor | metadata: status (potential/detected), technology, version, cpe. Sourced from the URL/host that runs the versioned technology, not from the version-less technology node |

Defined but not produced yet: `HOSTS`, `RELATED_TO`.

Discovered neighbours (IPs, CNAME targets, name servers) become assets and are linked to the
program with their **own** scope status (`out_of_scope` unless the program's scope covers them).
Being in the graph never authorises scanning: every job is scope-checked independently.
