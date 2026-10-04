# Notifications

Event-driven and provider-agnostic. No notification can trigger a command.

```
any component --EventEmitter--> bb:events:<pipeline> (Logstash)
                     └─ tap: notifiable event types --> bb:notify (bounded list, 100k)
notifier service --> NotificationPolicy match --> dedup --> provider (HTTPS / SMTP) --> delivery log
```

## Notification types and severities

| Platform event | Notification type | Severity |
|---|---|---|
| NEW_DOMAIN, NEW_URL | NEW_ASSET | info |
| NEW_SUBDOMAIN | NEW_SUBDOMAIN | info |
| NEW_IP | NEW_IP | info |
| CERT_EXPIRING / CERTIFICATE_EXPIRED | TLS_EXPIRING | medium / high |
| TLS_CHANGED | TLS_CHANGED | low |
| TECHNOLOGY_ADDED / REMOVED | TECHNOLOGY_CHANGED | low |
| NEW_CVE (correlation) | NEW_CVE | medium |
| KEV_ADDED (correlated CVE in CISA KEV) | NEW_KEV | critical |
| NEW_CRITICAL_FINDING | NEW_CRITICAL_FINDING | critical (nuclei worker, new critical finding) |
| SCAN_FAILURE (job will retry) | SCAN_FAILURE | low |
| DLQ_EVENT (job dead-lettered) | DLQ_EVENT | medium |

`GET /notifications/types` lists them. A policy matches on type (or `*`), optional program and
optional `min_severity`.

## Channels and secrets

Providers: `slack`, `discord`, `telegram`, `webhook`, `email` (`app/services/notify/providers.py`).
Secrets (webhook URLs, bot tokens, SMTP password, HMAC key) are **never stored**. A channel stores
`secret_ref`, the NAME of an env var or Docker secret (`/run/secrets/<NAME>`) resolved at send time.
The compose file passes `NOTIFY_SLACK_WEBHOOK`, `NOTIFY_DISCORD_WEBHOOK`, `NOTIFY_TELEGRAM_TOKEN`,
`NOTIFY_WEBHOOK_SECRET` and `NOTIFY_SMTP_PASSWORD` to the notifier and the orchestrator (for tests).

| Type | secret_ref holds | config |
|---|---|---|
| slack / discord | incoming webhook URL | — |
| telegram | bot token | `chat_id` |
| webhook | URL (if no `config.url`) or HMAC key when `sign: true` | `url`, `sign` (adds `X-BB-Signature: sha256=<hmac of body>`) |
| email | SMTP password | `host`, `port`, `username`, `from`, `to`, `starttls` |

Outbound safety: destinations must be `https://` and must not resolve to private, loopback,
link-local or reserved addresses, and redirects are not followed. `NOTIFY_ALLOW_PRIVATE_DESTINATIONS=true`
lifts this for lab use only (the dev `webhook-sink` receiver).

## Delivery semantics

* **Deduplication:** one delivery per (policy, notification type, underlying fact), enforced by a
  unique key in `notification_deliveries`. Example: a replayed job that fails again with the same
  error does not page twice.
* **Retries:** transient errors are retried after 30 s, 2 min and 8 min (4 attempts). Configuration
  errors (missing secret, HTTP 400/401/403/404) fail immediately. Failed deliveries go to
  `bb:dlq:notifications` (`bbctl dlq list notifications`, `bbctl dlq replay notifications`).
* **Rate limit:** `NOTIFY_RATE_PER_MINUTE` per channel (default 20). Excess messages are deferred,
  not dropped.
* **Observability:** every delivery is a row in `notification_deliveries` (`bbctl notify deliveries`),
  an event in `bb-notifications-*` (Recon Operations dashboard) and a `notifications_total{status}`
  metric. Channel and policy changes and tests are audited.

## Example

```bash
# .env: NOTIFY_SLACK_WEBHOOK=https://hooks.slack.com/services/...
./bbctl notify add-channel slack-alerts --type slack --secret-ref NOTIFY_SLACK_WEBHOOK
./bbctl notify test slack-alerts
./bbctl notify add-policy slack-alerts -e NEW_KEV -e NEW_CVE -e TLS_EXPIRING -e DLQ_EVENT -p acme --min-severity medium
./bbctl notify deliveries
```

Verified in the dev lab: test message plus a real `TLS_CHANGED` (from a tlsx re-scan after the lab
certificate rotated) and a `DLQ_EVENT` were delivered to the webhook sink with valid HMAC signatures,
and the duplicate `DLQ_EVENT` after a replay was suppressed.
