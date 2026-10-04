# User Authentication + Dynamic Settings — Design

Date: 2026-10-04
Status: approved for planning

## Goal

Replace the "paste an API key into a Connect field" UX in the management console (`/ui`) with a
real **username + password login**, and make a bounded set of operational configuration **dynamic**
(stored in PostgreSQL, editable from the UI) instead of only readable from `.env`.

Two subsystems, designed together, implemented together:

1. **User authentication** — DB-backed user accounts, first-run admin setup, JWT login.
2. **Dynamic settings** — a whitelist of operational knobs overridable at runtime via the DB, read
   by both the orchestrator and the workers.

## Non-goals / constraints

- API-key authentication **stays** and is unchanged. Workers, `bbctl`, and the autoscaler keep
  authenticating with API keys (non-interactive). Nothing that works today breaks.
- Infrastructure and secret configuration (database URL, Elasticsearch/Redis hosts, host ports,
  passwords, image versions, `BB_JWT_SECRET`) is **never** dynamic — it stays env-only and cannot
  be changed from the UI.
- Kibana remains the analytics UI. This work does not add analytics to the console.
- No SSO/OAuth, no email flows, no password reset via email. Admins reset passwords directly.

## Decisions (locked during brainstorming)

- API keys and user login **coexist**.
- Session transport is a **JWT stored in the browser's localStorage** (not an HttpOnly cookie).
  Accepted tradeoff: a JWT in localStorage is readable by JavaScript, so an XSS bug could exfiltrate
  it. Mitigated by the console serving no untrusted HTML and a short token lifetime. No CSRF
  handling is needed because the token is sent in an `Authorization` header, not a cookie.
- First admin is created dynamically via a **first-run setup screen** (no static credential in
  `.env`); everything lives in the DB.
- Dynamic settings use **approach A**: a whitelist of keys, DB override with a short-TTL cached
  resolver that falls back to the `.env` default. Infra stays env-only.

## Data model (PostgreSQL)

### `users`
| column | type | notes |
|---|---|---|
| id | uuid pk | |
| username | varchar(64) unique, not null | case-insensitive match (store lower) |
| password_hash | text not null | bcrypt |
| role | varchar(16) not null | reuse `Role` enum: `viewer` / `operator` / `admin` |
| active | bool not null default true | inactive users cannot log in |
| last_login_at | timestamptz null | |
| created_at / updated_at | timestamptz | via TimestampMixin |

### `settings`
| column | type | notes |
|---|---|---|
| key | varchar(64) pk | must be a member of `DYNAMIC_KEYS` |
| value | jsonb not null | typed per key |
| updated_by | varchar(128) null | principal name |
| updated_at | timestamptz | |

Only overridden keys have a row. A missing row means "use the `.env` default".

Migration `0008` creates both tables. No default user is seeded (first-run setup handles it). The
env API-key bootstrap (`BB_BOOTSTRAP_ADMIN_KEY`) is unchanged so CLI/workers work from first boot.

## Authentication

### Password hashing
- New pinned dependency: `bcrypt`. Helper `hash_password` / `verify_password` in `app/utils/hashing.py`
  (next to the existing `sha256_text`, which continues to hash API keys — unchanged).
- bcrypt has a 72-byte input limit; passwords are validated to a sensible max length (e.g. 128) and
  minimum length (e.g. 10) before hashing.

### JWT
- Signing secret `BB_JWT_SECRET` (env). If unset, the app derives one from an existing secret and
  logs a warning that it must be set explicitly for multi-replica orchestrators (tokens must verify
  across replicas). New pinned dependency: `pyjwt`.
- Token payload: `sub` = user id, `role`, `iat`, `exp`. Lifetime default 12h, exposed later as a
  dynamic setting (`AUTH_TOKEN_TTL_SECONDS`).
- Algorithm HS256.

### Principal resolution (the one shared change)
`app/api/deps.py::get_principal` is extended to accept **either**:
- `Authorization: Bearer <jwt>` → verify + load user → `Principal(name=username, role=user.role)`;
  reject if the user is missing/inactive or the token is expired/invalid.
- `X-API-Key: <key>` → current behaviour, unchanged.

If both are absent → 401. `require(role)` / `viewer` / `operator` / `admin` are unchanged, so every
existing endpoint gains JWT support for free. Precedence: if a Bearer token is present it is used;
otherwise the API key.

### Endpoints
Public (no auth):
- `GET /auth/needs-setup` → `{ "needs_setup": <bool> }` (true when the `users` table is empty).
- `POST /auth/setup { username, password }` → creates the first **admin**. Allowed **only** while
  zero users exist; returns 409 afterwards. Returns a token.
- `POST /auth/login { username, password }` → `{ token, user }`; 401 on bad credentials or inactive
  user. Updates `last_login_at`.

Authenticated:
- `GET /auth/me` → the current user.
- `POST /auth/password { current_password, new_password }` → change own password.

Admin only:
- `GET /users`, `POST /users { username, password, role }`, `PATCH /users/{id} { role?, active?,
  password? }`, `DELETE /users/{id}`. An admin cannot delete or deactivate the last active admin
  (guard against lockout).

Admin only (settings):
- `GET /settings` → every dynamic key with `{ key, value, source: "env"|"override", default }`.
- `PUT /settings/{key} { value }` → validate against the key's type/bounds, upsert the override.
- `DELETE /settings/{key}` → remove the override (revert to env default).

All user and settings mutations are written to the audit log (`user.created`, `user.changed`,
`user.deleted`, `auth.login`, `auth.setup`, `settings.changed`, `settings.reverted`).

## Dynamic settings (approach A)

- `app/services/settings_store.py` exposes `dynamic_setting(key)`:
  1. look up `settings` (cached in Redis or in-process with a ~30–60s TTL),
  2. fall back to the `.env` value from `get_settings()`.
- `DYNAMIC_KEYS`: a registry mapping each dynamic key to a type + validation bounds. Initial set:
  - scanner rate limits: `HTTPX_RATE_LIMIT`, `TLSX_RATE_LIMIT`, `NUCLEI_RATE_LIMIT`,
    `KATANA_RATE_LIMIT`, `BBOT_RATE_LIMIT`;
  - resource limits: `MAX_CONCURRENCY`, `MAX_CIDR_SIZE`, `MAX_IPS_PER_JOB`, `MAX_URLS_PER_CRAWL`,
    `MAX_CRAWL_DEPTH`, `MAX_SCAN_DURATION`;
  - discovery/identity: `CERTSTREAM_FOLLOWUP_SCANNERS`, `BB_REQUEST_HEADER`, `BB_USER_AGENT`;
  - autoscale: `AUTOSCALE_*`;
  - auth: `AUTH_TOKEN_TTL_SECONDS`.
- Keys **not** in the registry are rejected by `PUT /settings/{key}`. Infra/secret keys are never in
  the registry.
- Call sites that must honour overrides read the key through `dynamic_setting()` instead of
  `get_settings().<field>`. This touches the orchestrator and the workers for the whitelisted keys
  only; everything else keeps using `get_settings()`. Because of the TTL cache, a change applies
  within the TTL window without restarting any container.
- Validation reuses the same bounds the policy/settings layer already enforces, so an override can
  never set an out-of-range value.

## UI (`/ui`)

- Remove the header "API base / API key / Connect" controls.
- Gate the app behind auth:
  - no token → **Login** screen (username + password → `POST /auth/login` → store JWT in
    localStorage).
  - `GET /auth/needs-setup` true → **Create first admin** screen (`POST /auth/setup`).
  - authenticated → header shows `username (role)` and a **Logout** button (clears the token).
- Every API call sends `Authorization: Bearer <jwt>`. A 401 sends the user back to the login screen.
- New admin-only tabs:
  - **Users** — list / create / edit role & active / reset password / delete.
  - **Settings** — list dynamic keys with effective value and source (env/override), edit, and
    reset-to-default.
- Existing tabs (Watch, Programs, Scope, Scan, Jobs, Policies, Schedules, Stats) are unchanged apart
  from using the JWT.

## CLI

- `bbctl` keeps using the API key (unchanged; non-interactive).
- Add admin helpers over the same API: `bbctl user list|create|delete`, `bbctl settings
  list|set|unset`. Optional but included for parity with the UI.

## Configuration (.env additions)

- `BB_JWT_SECRET` — HS256 signing secret (required for multi-replica; warn if unset).
- `AUTH_TOKEN_TTL_SECONDS` — default 43200 (12h); also a dynamic key.
No user credentials are placed in `.env` (first-run setup owns that).

## Testing

Unit:
- password hash/verify (correct, wrong, length bounds);
- JWT issue/verify/expired/wrong-secret;
- `get_principal` accepts a valid JWT, rejects expired/inactive, still accepts an API key;
- settings resolver: override wins, fallback to env, unknown key rejected, out-of-bounds rejected;
- last-admin lockout guard.

Integration (live stack):
- `needs-setup` true on empty → `setup` creates admin → `login` works → authed request succeeds;
- `setup` returns 409 once a user exists;
- bad login 401; inactive user 401;
- non-admin JWT rejected (403) on `/users` and `/settings`; admin allowed;
- `PUT /settings/HTTPX_RATE_LIMIT` changes the effective value; `DELETE` reverts it;
- an API-key client still works alongside JWT.

## Security considerations

- JWT-in-localStorage XSS exposure (accepted, mitigated by short TTL + trusted-only HTML).
- First-run setup endpoint is open only while there are zero users; run setup behind a firewall/IP
  allowlist. It returns 409 forever after.
- Infra/secret settings are never dynamic, so the UI cannot break DB/ES connectivity or weaken
  transport.
- bcrypt for passwords (slow KDF); sha256 remains only for high-entropy API keys.
- Last-admin guard prevents locking everyone out.
- `BB_JWT_SECRET` must be identical across orchestrator replicas.

## Migration / rollout

1. Migration `0008` adds `users` + `settings` (no data).
2. Deploy. On first open, the console shows "create first admin".
3. API keys keep working throughout; the CLI/workers are unaffected.
4. Dynamic settings start empty → behaviour identical to today (env defaults) until an admin sets an
   override.

## Open items to confirm at plan time

- Exact initial contents of `DYNAMIC_KEYS` (the list above is the starting proposal).
- JWT default TTL (12h proposed).
- Whether `bbctl user` / `bbctl settings` ship in this iteration or later.
