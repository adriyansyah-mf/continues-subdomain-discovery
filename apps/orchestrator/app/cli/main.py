"""bbctl - command line client for the orchestrator API.

Configuration (environment):
  BB_API_URL   default http://127.0.0.1:18000
  BB_API_KEY   API key (falls back to BB_BOOTSTRAP_ADMIN_KEY)
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import httpx
import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Bug bounty asset intelligence platform CLI", no_args_is_help=True)
program_app = typer.Typer(help="Programs", no_args_is_help=True)
scope_app = typer.Typer(help="Scope (CDB) entries", no_args_is_help=True)
asset_app = typer.Typer(help="Assets", no_args_is_help=True)
scan_app = typer.Typer(help="Scans and jobs", no_args_is_help=True)
worker_app = typer.Typer(help="Workers and queues", no_args_is_help=True)
bootstrap_app = typer.Typer(help="Bootstrap data sources", no_args_is_help=True)
sync_app = typer.Typer(help="Synchronise external feeds", no_args_is_help=True)
policy_app = typer.Typer(help="Scan policies", no_args_is_help=True)
schedule_app = typer.Typer(help="Periodic schedules", no_args_is_help=True)
notify_app = typer.Typer(help="Notification channels, policies and deliveries", no_args_is_help=True)
dlq_app = typer.Typer(help="Dead-letter queues", no_args_is_help=True)
maint_app = typer.Typer(help="Maintenance windows", no_args_is_help=True)
for name, sub in (
    ("program", program_app),
    ("scope", scope_app),
    ("asset", asset_app),
    ("scan", scan_app),
    ("worker", worker_app),
    ("bootstrap", bootstrap_app),
    ("sync", sync_app),
    ("policy", policy_app),
    ("schedule", schedule_app),
    ("notify", notify_app),
    ("dlq", dlq_app),
    ("maintenance", maint_app),
):
    app.add_typer(sub, name=name)

console = Console()
JSON_OPT = typer.Option(False, "--json", help="print raw JSON")


def _client() -> httpx.Client:
    url = os.environ.get("BB_API_URL", "http://127.0.0.1:18000")
    key = os.environ.get("BB_API_KEY") or os.environ.get("BB_BOOTSTRAP_ADMIN_KEY")
    if not key:
        console.print("[red]BB_API_KEY is not set[/red]")
        raise typer.Exit(2)
    return httpx.Client(base_url=url, headers={"X-API-Key": key}, timeout=300)


def _call(method: str, path: str, **kwargs: Any) -> Any:
    try:
        with _client() as c:
            r = c.request(method, path, **kwargs)
    except httpx.HTTPError as exc:
        console.print(f"[red]API unreachable: {exc}[/red]")
        raise typer.Exit(1) from exc
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = r.text
        console.print(
            f"[red]{r.status_code}[/red] {json.dumps(detail, indent=2) if not isinstance(detail, str) else detail}"
        )
        raise typer.Exit(1)
    return r.json() if r.content else None


def _table(rows: list[dict], columns: list[str], title: str | None = None) -> None:
    t = Table(title=title, show_lines=False)
    for col in columns:
        t.add_column(col)
    for row in rows:
        t.add_row(*["" if row.get(c) is None else str(row.get(c)) for c in columns])
    console.print(t)


def _out(data: Any, as_json: bool, columns: list[str] | None = None, title: str | None = None) -> None:
    if as_json or columns is None:
        console.print_json(json.dumps(data, default=str))
    else:
        _table(data, columns, title)


# --- health ------------------------------------------------------------------
@app.command()
def health() -> None:
    """Show API readiness (PostgreSQL / Redis / Elasticsearch)."""
    url = os.environ.get("BB_API_URL", "http://127.0.0.1:18000")
    try:
        r = httpx.get(f"{url}/ready", timeout=15)
    except httpx.HTTPError as exc:
        console.print(f"[red]orchestrator unreachable: {exc}[/red]")
        raise typer.Exit(1) from exc
    console.print_json(r.text)
    raise typer.Exit(0 if r.status_code == 200 else 1)


# --- programs ----------------------------------------------------------------
@program_app.command("list")
def program_list(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/programs"), as_json, ["slug", "name", "platform", "active", "id"])


@program_app.command("create")
def program_create(
    name: str,
    slug: str | None = typer.Option(None),
    platform: str = typer.Option("custom"),
    description: str | None = typer.Option(None),
    policy: str | None = typer.Option(None, help="default scan policy name"),
    inactive: bool = typer.Option(False, help="create paused"),
    as_json: bool = JSON_OPT,
) -> None:
    body = {
        "name": name,
        "slug": slug,
        "platform": platform,
        "description": description,
        "default_policy": policy,
        "active": not inactive,
    }
    _out(_call("POST", "/programs", json=body), as_json)


@program_app.command("update")
def program_update(
    program: str,
    active: bool | None = typer.Option(None, "--active/--inactive"),
    policy: str | None = typer.Option(None),
    name: str | None = typer.Option(None),
) -> None:
    body: dict[str, Any] = {}
    if active is not None:
        body["active"] = active
    if policy is not None:
        body["default_policy"] = policy
    if name is not None:
        body["name"] = name
    _out(_call("PATCH", f"/programs/{program}", json=body), True)


@program_app.command("targets")
def program_targets(
    program: str,
    kind: str = typer.Option("host", help="host | url"),
    out: str | None = typer.Option(
        None,
        "--out",
        "-o",
        help="write to this file (via ./bbctl it is inside the container; prefer > redirection)",
    ),
) -> None:
    """In-scope targets for a program (re-verified server-side) - e.g. an input list for external Nuclei."""
    res = _call("GET", f"/programs/{program}/targets", params={"kind": kind})
    if out:
        with open(out, "w") as fh:
            fh.write("\n".join(res["targets"]) + ("\n" if res["targets"] else ""))
        console.print(
            f"{res['count']} in-scope {kind} target(s) -> {out} ({res['skipped_out_of_scope']} skipped as out of scope)"
        )
    else:
        for t in res["targets"]:
            print(t)


@program_app.command("delete")
def program_delete(program: str, yes: bool = typer.Option(False, "--yes", help="skip confirmation")) -> None:
    """Soft-delete (deactivate and hide) a program."""
    if not yes:
        typer.confirm(f"Delete program {program}?", abort=True)
    _call("DELETE", f"/programs/{program}")
    console.print(f"program {program} deleted")


# --- scope -------------------------------------------------------------------
@scope_app.command("list")
def scope_list(
    program: str = typer.Option(None, "--program", "-p", help="program id or slug (default: all)"),
    limit: int = 200,
    as_json: bool = JSON_OPT,
) -> None:
    programs = [{"slug": program}] if program else _call("GET", "/programs")
    rows = []
    for p in programs:
        for e in _call("GET", f"/programs/{p['slug']}/scope", params={"limit": limit}):
            rows.append({**e, "program": p["slug"]})
    _out(rows, as_json, ["program", "mode", "type", "normalized_value", "source", "id"])


@scope_app.command("add")
def scope_add(
    program: str,
    value: str,
    mode: str = typer.Option("include", help="include|exclude"),
    type_: str | None = typer.Option(None, "--type", help="domain|wildcard|cidr|ipv4|ipv6|asn|url"),
    description: str | None = typer.Option(None),
) -> None:
    body = {"value": value, "mode": mode, "type": type_, "description": description}
    _out(_call("POST", f"/programs/{program}/scope", json=body), True)


@scope_app.command("remove")
def scope_remove(scope_id: str) -> None:
    _call("DELETE", f"/scope/{scope_id}")
    console.print(f"scope entry {scope_id} removed")


@scope_app.command("check")
def scope_check(target: str, program: str | None = typer.Option(None, "--program", "-p")) -> None:
    """Explain whether (and why) a target is in scope."""
    program_id = _call("GET", f"/programs/{program}")["id"] if program else None
    _out(_call("POST", "/scope/check", json={"target": target, "program_id": program_id}), True)


# --- assets ------------------------------------------------------------------
@asset_app.command("list")
def asset_list(
    program: str | None = typer.Option(None, "--program", "-p"),
    type_: str | None = typer.Option(None, "--type"),
    q: str | None = typer.Option(None),
    limit: int = 50,
    as_json: bool = JSON_OPT,
) -> None:
    params = {k: v for k, v in {"program": program, "type": type_, "q": q, "limit": limit}.items() if v}
    _out(
        _call("GET", "/assets", params=params),
        as_json,
        ["asset_type", "normalized_value", "status", "lifecycle_stage", "last_seen", "id"],
    )


@asset_app.command("show")
def asset_show(asset_id: str, relationships: bool = typer.Option(True)) -> None:
    data = _call("GET", f"/assets/{asset_id}")
    if relationships:
        data["relationships"] = _call("GET", f"/assets/{asset_id}/relationships")
    _out(data, True)


# --- scans -------------------------------------------------------------------
@scan_app.command("run")
def scan_run(
    program: str = typer.Option(..., "--program", "-p"),
    target: list[str] = typer.Option(None, "--target", "-t", help="target value (repeatable)"),
    asset: list[str] = typer.Option(None, "--asset", "-a", help="asset id (repeatable)"),
    scanner: list[str] = typer.Option(["httpx"], "--scanner", "-s", help="scanner (repeatable)"),
    policy: str | None = typer.Option(None),
    priority: int = 5,
    force: bool = typer.Option(False, help="bypass idempotency deduplication"),
    as_json: bool = JSON_OPT,
) -> None:
    body = {
        "program": program,
        "targets": target or [],
        "asset_ids": asset or [],
        "scanners": scanner,
        "policy": policy,
        "priority": priority,
        "force": force,
    }
    res = _call("POST", "/scans", json=body)
    if as_json:
        _out(res, True)
        return
    console.print(f"scan [bold]{res['scan']['id']}[/bold] summary={res['summary']}")
    _table(res["jobs"], ["scanner", "target", "status", "block_reason", "scope_reason", "id"])


@scan_app.command("status")
def scan_status(scan_id: str | None = typer.Argument(None), as_json: bool = JSON_OPT) -> None:
    if scan_id is None:
        _out(_call("GET", "/scans"), as_json, ["id", "status", "scanners", "trigger", "requested_by", "created_at"])
        return
    scan = _call("GET", f"/scans/{scan_id}")
    jobs = _call("GET", "/jobs", params={"scan_id": scan_id})
    if as_json:
        _out({"scan": scan, "jobs": jobs}, True)
        return
    console.print(f"scan {scan['id']} status={scan['status']} jobs={scan['job_counts']}")
    _table(jobs, ["scanner", "target", "status", "retry_count", "error", "result_summary", "id"])


@scan_app.command("cancel")
def scan_cancel(scan_id: str) -> None:
    _out(_call("POST", f"/scans/{scan_id}/cancel"), True)


@scan_app.command("jobs")
def scan_jobs(
    status: str | None = typer.Option(None),
    scanner: str | None = typer.Option(None),
    limit: int = 50,
    as_json: bool = JSON_OPT,
) -> None:
    params = {k: v for k, v in {"status": status, "scanner": scanner, "limit": limit}.items() if v}
    _out(
        _call("GET", "/jobs", params=params),
        as_json,
        ["scanner", "target", "status", "block_reason", "retry_count", "created_at", "id"],
    )


# --- workers -----------------------------------------------------------------
@worker_app.command("status")
def worker_status(as_json: bool = JSON_OPT) -> None:
    data = _call("GET", "/workers")
    queues = _call("GET", "/queues")["depths"]
    if as_json:
        _out({**data, "queues": queues}, True)
        return
    _table(data["workers"], ["worker_id", "queue", "tool_version", "current_job"], "Live workers")
    _table([{"queue": k, **v} for k, v in queues.items()], ["queue", "pending", "dlq"], "Queues")
    _table(data["scanners"], ["name", "queue", "implemented", "active", "description"], "Scanners")


@worker_app.command("pause")
def worker_pause(scanner: str, reason: str = typer.Option("paused via bbctl")) -> None:
    _out(_call("PUT", f"/scanners/{scanner}", json={"paused": True, "reason": reason}), True)


@worker_app.command("resume")
def worker_resume(scanner: str) -> None:
    _out(_call("PUT", f"/scanners/{scanner}", json={"paused": False}), True)


# --- bootstrap / sync -----------------------------------------------------------
@bootstrap_app.command("bounty-targets")
def bootstrap_bounty_targets() -> None:
    """Import arkadiyt/bounty-targets-data domains.txt (diffed against the previous import)."""
    res = _call("POST", "/sync/bounty-targets")
    _out(res, True)


@sync_app.command("ipranges")
def sync_ipranges() -> None:
    _out(_call("POST", "/sync/ipranges"), True)


@sync_app.command("asn")
def sync_asn() -> None:
    """IP -> ASN enrichment data (iptoasn.com)."""
    _out(_call("POST", "/sync/asn"), True)


@sync_app.command("epss")
def sync_epss() -> None:
    _out(_call("POST", "/sync/epss"), True)


@sync_app.command("kev")
def sync_kev() -> None:
    _out(_call("POST", "/sync/kev"), True)


@sync_app.command("cve")
def sync_cve(force: bool = typer.Option(False, help="ignore the 7-day NVD lookup cache")) -> None:
    _out(_call("POST", "/sync/cve", params={"force": force}), True)


# --- policies / schedules -------------------------------------------------------
@policy_app.command("list")
def policy_list(as_json: bool = JSON_OPT) -> None:
    data = _call("GET", "/policies")
    if as_json:
        _out(data, True)
        return
    rows = [
        {
            "name": p["name"],
            "enabled": ",".join(k for k, v in p["config"].items() if v.get("enabled")),
            "description": p["description"],
        }
        for p in data
    ]
    _table(rows, ["name", "enabled", "description"])


@policy_app.command("create")
def policy_create(name: str, config_file: typer.FileText, description: str | None = typer.Option(None)) -> None:
    _out(
        _call("POST", "/policies", json={"name": name, "description": description, "config": json.load(config_file)}),
        True,
    )


@policy_app.command("show")
def policy_show(name: str) -> None:
    """Print one policy (its config can be edited and passed to `policy update`)."""
    match = [p for p in _call("GET", "/policies") if p["name"] == name]
    if not match:
        console.print(f"[red]policy {name!r} not found[/red]")
        raise typer.Exit(1)
    _out(match[0], True)


@policy_app.command("update")
def policy_update(name: str, config_file: typer.FileText, description: str | None = typer.Option(None)) -> None:
    """Replace a policy's config with the JSON in CONFIG_FILE (validated + audited server-side)."""
    _out(
        _call(
            "PUT",
            f"/policies/{name}",
            json={"name": name, "description": description, "config": json.load(config_file)},
        ),
        True,
    )


@policy_app.command("delete")
def policy_delete(name: str, yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        typer.confirm(f"Delete policy {name}?", abort=True)
    _call("DELETE", f"/policies/{name}")
    console.print(f"policy {name} deleted")


@schedule_app.command("list")
def schedule_list(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/schedules"), as_json, ["name", "scanner", "enabled", "interval_seconds", "next_run_at"])


@schedule_app.command("enable")
def schedule_enable(
    name: str, program: str | None = typer.Option(None), policy: str | None = typer.Option(None)
) -> None:
    body: dict[str, Any] = {"enabled": True}
    if program:
        body["program"] = program
    if policy:
        body["policy"] = policy
    _out(_call("PATCH", f"/schedules/{name}", json=body), True)


@schedule_app.command("disable")
def schedule_disable(name: str) -> None:
    _out(_call("PATCH", f"/schedules/{name}", json={"enabled": False}), True)


# --- notifications -------------------------------------------------------------
@notify_app.command("types")
def notify_types() -> None:
    _out(_call("GET", "/notifications/types"), True)


@notify_app.command("channels")
def notify_channels(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/notifications/channels"), as_json, ["name", "channel_type", "secret_ref", "enabled", "config"])


@notify_app.command("add-channel")
def notify_add_channel(
    name: str,
    channel_type: str = typer.Option(..., "--type", help="slack|discord|telegram|webhook|email"),
    secret_ref: str | None = typer.Option(None, help="NAME of the env var / Docker secret holding the secret"),
    config: str = typer.Option("{}", help='JSON, e.g. \'{"chat_id": "123"}\''),
) -> None:
    body = {"name": name, "channel_type": channel_type, "secret_ref": secret_ref, "config": json.loads(config)}
    _out(_call("POST", "/notifications/channels", json=body), True)


@notify_app.command("remove-channel")
def notify_remove_channel(name: str) -> None:
    _call("DELETE", f"/notifications/channels/{name}")
    console.print(f"channel {name} removed")


@notify_app.command("test")
def notify_test(name: str) -> None:
    _out(_call("POST", f"/notifications/channels/{name}/test"), True)


@notify_app.command("policies")
def notify_policies(as_json: bool = JSON_OPT) -> None:
    _out(
        _call("GET", "/notifications/policies"),
        as_json,
        ["id", "channel", "event_types", "min_severity", "program_id", "enabled"],
    )


@notify_app.command("add-policy")
def notify_add_policy(
    channel: str,
    event: list[str] = typer.Option(..., "--event", "-e", help="notification type (repeatable) or *"),
    program: str | None = typer.Option(None, "--program", "-p"),
    min_severity: str | None = typer.Option(None),
) -> None:
    body = {"channel": channel, "event_types": event, "program": program, "min_severity": min_severity}
    _out(_call("POST", "/notifications/policies", json=body), True)


@notify_app.command("remove-policy")
def notify_remove_policy(policy_id: str) -> None:
    _call("DELETE", f"/notifications/policies/{policy_id}")
    console.print(f"policy {policy_id} removed")


@notify_app.command("deliveries")
def notify_deliveries(status: str | None = typer.Option(None), limit: int = 30, as_json: bool = JSON_OPT) -> None:
    params: dict[str, Any] = {"limit": limit, **({"status": status} if status else {})}
    _out(
        _call("GET", "/notifications/deliveries", params=params),
        as_json,
        ["created_at", "event_type", "severity", "status", "attempts", "summary", "last_error"],
    )


# --- dead-letter queues --------------------------------------------------------
@dlq_app.command("list")
def dlq_list(queue: str) -> None:
    _out(_call("GET", "/queues", params={"dlq": queue}).get("dlq_items", []), True)


@dlq_app.command("replay")
def dlq_replay(queue: str, limit: int = 50) -> None:
    _out(_call("POST", f"/queues/{queue}/dlq/replay", params={"limit": limit}), True)


@dlq_app.command("purge")
def dlq_purge(queue: str, yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        typer.confirm(f"Permanently delete all dead-lettered items of {queue}?", abort=True)
    _out(_call("DELETE", f"/queues/{queue}/dlq"), True)


# --- maintenance windows -------------------------------------------------------
@maint_app.command("list")
def maint_list(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/maintenance-windows"), as_json, ["id", "program_id", "scanner", "start", "end", "reason"])


@maint_app.command("add")
def maint_add(
    start: str = typer.Option(..., help="ISO-8601, e.g. 2026-10-05T22:00:00Z"),
    end: str = typer.Option(..., help="ISO-8601"),
    reason: str = typer.Option(...),
    program: str | None = typer.Option(None, "--program", "-p"),
    scanner: str | None = typer.Option(None),
) -> None:
    body = {"start": start, "end": end, "reason": reason, "program": program, "scanner": scanner}
    _out(_call("POST", "/maintenance-windows", json=body), True)


@app.command()
def stats() -> None:
    _out(_call("GET", "/stats"), True)


if __name__ == "__main__":
    sys.exit(app())
