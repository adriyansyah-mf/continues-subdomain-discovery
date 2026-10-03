# Scope engine

Code: `app/scope/normalize.py` (strict parsing), `app/scope/engine.py` (pure evaluation),
`app/scope/service.py` (loads rules from PostgreSQL, fails closed),
`workers/common/scope_guard.py` (worker layers). Tests: `tests/unit/test_scope_engine.py`,
`tests/unit/test_normalize.py`, `tests/integration/test_platform.py`.

## API

```python
ScopeEngine(rules).is_in_scope("api.example.com", program_id)
# allowed: {"allowed": true, "program_id": "...", "scope_id": "...", "reason": "matched *.example.com (wildcard)",
#           "match_kind": "wildcard_inclusion", ...}
# blocked: {"allowed": false, "reason": "not in approved scope", ...}
```

HTTP: `POST /scope/check {"target": "...", "program_id": "..."}`; CLI: `bbctl scope check <target> -p <program>`.
Without `program_id`, all programs are evaluated and `allowed_program_ids` lists every program
that allows the target.

## Precedence (per program)

1. **explicit exclusion** → blocked (always wins)
2. **explicit inclusion** (exact domain, IP, CIDR containment, URL prefix, ASN) → allowed
3. **inherited wildcard inclusion** → allowed
4. otherwise → not in scope

Exclusions in one program never affect another program.

## Matching rules

| Rule | Matches |
|---|---|
| include `domain example.com` | exactly `example.com` |
| include `wildcard *.example.com` | any depth below, on label boundaries (`a.b.example.com`); **not** the apex, not `evilexample.com` |
| exclude `domain admin.example.com` | the host **and everything beneath it** (conservative) |
| exclude `wildcard *.x.example.com` | everything beneath `x.example.com` |
| include `cidr` / `ipv4` / `ipv6` | IPs inside; a CIDR target must be entirely inside |
| exclude `cidr` / IP | any target that *overlaps* (a /24 containing one excluded IP is blocked; ranges are not split) |
| include `url https://h/app` | URLs with the same scheme, host, port and a path prefix on segment boundaries (`/app`, `/app/x`, not `/apple`). Never authorises host-level scans |
| exclude `url` | matching URLs (path prefix). Host-level targets are blocked only if the whole origin is excluded (`https://host/`); narrower URL exclusions must be enforced by path-exploring scanners (katana turns them into `-cos` regexes and re-checks every output URL; nuclei must do the same before it may run) |
| `asn` | ASN targets only. An ASN rule does **not** authorise IPs (no reliable ownership resolution) |

## Normalization / bypass resistance

Rejected (fail closed) rather than guessed: empty labels, numeric or hex "TLDs" (`127.1`,
`0x7f.0x1`, `2130706433`), IPv6 zone ids, URLs with userinfo (`https://good@evil`), backslashes,
whitespace or control characters, non-http(s) schemes, `host:port` without scheme, wildcard forms
other than a single leading `*.` (`api-*.example.com`, `*example.com`), wildcards over a public
suffix (`*.com`, `*.co.uk`, using tldextract's bundled list — no network fetch), CIDRs with host
bits set. IDN labels are converted to punycode (UTS-46); IPv4-mapped IPv6 is normalized to IPv4;
URL paths are percent-decoded and dot-segments resolved before matching, so
`/public/..%2fprivate` matches an exclusion on `/private`.

## Performance

Domain and wildcard rules are indexed per program by domain, so an evaluation only inspects rules
attached to the host's suffixes (plus the usually small set of IP/CIDR/URL/ASN rules). With 37k
domain rules this is ~100k evaluations/s in one process, enough for CertStream.

## Defense in depth

| Layer | Where | What |
|---|---|---|
| 1 | orchestrator `ScanService` | fresh scope evaluation; operational guards; policy; CIDR limits |
| 2 | worker `ScopeGuard.check_target` | re-evaluates against freshly loaded rules when the job starts (scope may have changed since queueing) |
| 2b | worker `resolve_and_pin` | resolves the host; refuses private/loopback/link-local/CGNAT/reserved addresses unless that IP is explicitly in scope (`ALLOW_PRIVATE_TARGETS=false`); pins the validated IPs (`httpx -allow`, `tlsx -u <ip> -sni <host>`) against DNS rebinding |
| 3 | worker `validate_output` | every URL/host/IP in tool output is re-checked; out-of-scope results are dropped and reported |
| 4 | limits | `MAX_CIDR_SIZE`, `MAX_IPS_PER_JOB` → `BLOCKED/CIDR_LIMIT_EXCEEDED` |
| 5 | rate/concurrency | policy rate limits (capped by global env caps), Redis concurrency slots (`MAX_CONCURRENT_SCANS`), job wall-clock limit |

Any rejection records `SCOPE_BLOCKED` in `audit_events` (target, program, scope, scanner,
reason, layer, timestamp) and emits a `SCOPE_BLOCKED` event to `bb-changes-*`.

Scope that cannot be loaded or parsed (database down, corrupt row) → nothing is scanned.
